import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock openapi-fetch — importing api.ts triggers module-level createClient()
vi.mock('openapi-fetch', () => ({
    default: () => ({ use: vi.fn() }),
}));

import { createAuthMiddleware } from '$lib/api';
import { AuthRefreshManager } from '$lib/auth-refresh-manager';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createStorageMock(): Storage {
    const store = new Map<string, string>();
    return {
        getItem: (key) => store.get(key) ?? null,
        setItem: (key, value) => store.set(key, String(value)),
        removeItem: (key) => {
            store.delete(key);
        },
        clear: () => store.clear(),
        get length() {
            return store.size;
        },
        key: (i) => [...store.keys()][i] ?? null,
    };
}

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AuthRefreshManager', () => {
    let manager: AuthRefreshManager;
    let mockFetch: ReturnType<typeof vi.fn> & typeof fetch;

    beforeEach(() => {
        vi.useFakeTimers();
        vi.spyOn(Math, 'random').mockReturnValue(0); // deterministic jitter
        vi.stubGlobal('localStorage', createStorageMock());
        mockFetch = vi.fn() as ReturnType<typeof vi.fn> & typeof fetch;
        manager = new AuthRefreshManager(mockFetch);
    });

    afterEach(() => {
        manager.clearRefreshTimer();
        vi.useRealTimers();
        vi.restoreAllMocks();
        vi.unstubAllGlobals();
    });

    // -----------------------------------------------------------------------
    // 1. resolveRefreshParams — persists both keys with correct values
    // -----------------------------------------------------------------------
    describe('resolveRefreshParams (via setupRefreshTimer)', () => {
        it('stores expiry and 60s lead time for long-lived tokens', () => {
            vi.setSystemTime(1_000_000);
            manager.setupRefreshTimer(300);

            const storedExpiry = parseInt(localStorage.getItem('auth_expires_at')!, 10);
            expect(storedExpiry).toBe(1_000_000 + 300_000);
            expect(localStorage.getItem('auth_lead_time_ms')).toBe('60000');
        });

        it('stores 15s lead time for short-lived tokens (< 120s)', () => {
            manager.setupRefreshTimer(60);
            expect(localStorage.getItem('auth_lead_time_ms')).toBe('15000');
        });
    });

    // -----------------------------------------------------------------------
    // 2. resolveRefreshParams without arg — reads from localStorage
    // -----------------------------------------------------------------------
    describe('setupRefreshTimer without expiresInSeconds', () => {
        it('reads stored expiry and reschedules', () => {
            const future = Date.now() + 300_000;
            localStorage.setItem('auth_expires_at', future.toString());
            localStorage.setItem('auth_lead_time_ms', '60000');

            // Should not throw — timer is set from stored values
            manager.setupRefreshTimer();
        });

        it('no-ops when no stored expiry exists', () => {
            manager.setupRefreshTimer();
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it('no-ops when stored expiry is corrupt', () => {
            localStorage.setItem('auth_expires_at', 'garbage');
            manager.setupRefreshTimer();
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it('defaults lead time to 60s and fires at expiresAt - 60_000', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 300 }));

            vi.setSystemTime(0);
            localStorage.setItem('auth_expires_at', '300000');
            // No auth_lead_time_ms — should default to 60_000
            // delay = 300_000 - 0 - 60_000 - 0 = 240_000

            manager.setupRefreshTimer();

            await vi.advanceTimersByTimeAsync(239_999);
            expect(mockFetch).not.toHaveBeenCalled();

            await vi.advanceTimersByTimeAsync(1);
            expect(mockFetch).toHaveBeenCalledOnce();
        });
    });

    // -----------------------------------------------------------------------
    // 3. Timer fires at the correct delay
    // -----------------------------------------------------------------------
    describe('timer delay calculation', () => {
        it('fires at expiresAt minus leadTime (jitter mocked to 0)', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 300 }));

            vi.setSystemTime(0);
            manager.setupRefreshTimer(300); // expiresAt=300_000, leadTime=60_000
            // delay = 300_000 - 0 - 60_000 - 0(jitter) = 240_000

            // 1ms before — no fetch
            await vi.advanceTimersByTimeAsync(239_999);
            expect(mockFetch).not.toHaveBeenCalled();

            // At 240_000 — proactiveRefresh fires → calls fetch
            await vi.advanceTimersByTimeAsync(1);
            expect(mockFetch).toHaveBeenCalledOnce();
        });

        it('cancels the previous timer when called again', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 600 }));

            vi.setSystemTime(0);
            manager.setupRefreshTimer(300); // timer at 240_000
            manager.setupRefreshTimer(600); // replaces → timer at 540_000

            // Past first timer's delay — should NOT fire (cancelled)
            await vi.advanceTimersByTimeAsync(240_000);
            expect(mockFetch).not.toHaveBeenCalled();

            // At second timer's delay — should fire
            await vi.advanceTimersByTimeAsync(300_000);
            expect(mockFetch).toHaveBeenCalledOnce();
        });
    });

    // -----------------------------------------------------------------------
    // 4. Expired token — immediate proactive refresh
    // -----------------------------------------------------------------------
    describe('setupRefreshTimer with already-expired token', () => {
        it('triggers immediate refresh when delay <= 0', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 300 }));

            manager.setupRefreshTimer(1); // 1s expiry, 15s lead → delay < 0
            await vi.advanceTimersByTimeAsync(0); // flush microtasks

            expect(mockFetch).toHaveBeenCalledOnce();
        });
    });

    // -----------------------------------------------------------------------
    // 5. coalescedRefresh — deduplication
    // -----------------------------------------------------------------------
    describe('coalescedRefresh', () => {
        it('coalesces concurrent calls into a single fetch', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 300 }));

            const [r1, r2] = await Promise.all([
                manager.coalescedRefresh(),
                manager.coalescedRefresh(),
            ]);

            expect(r1).toBe(true);
            expect(r2).toBe(true);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it('starts a new fetch after the previous one completes', async () => {
            mockFetch.mockResolvedValue(jsonResponse({ expires_in: 300 }));

            await manager.coalescedRefresh();
            await manager.coalescedRefresh();

            expect(mockFetch).toHaveBeenCalledTimes(2);
        });
    });

    // -----------------------------------------------------------------------
    // 6. doRefresh success — reschedules timer from response
    // -----------------------------------------------------------------------
    describe('doRefresh success', () => {
        it('returns true and stores new expiry', async () => {
            mockFetch.mockResolvedValueOnce(jsonResponse({ expires_in: 300 }));

            const result = await manager.coalescedRefresh();

            expect(result).toBe(true);
            expect(localStorage.getItem('auth_expires_at')).not.toBeNull();
            expect(localStorage.getItem('auth_lead_time_ms')).toBe('60000');
        });

        it('falls back to stored expiry on JSON parse failure', async () => {
            // Pre-store so setupRefreshTimer() without args has something to read
            const future = Date.now() + 600_000;
            localStorage.setItem('auth_expires_at', future.toString());
            localStorage.setItem('auth_lead_time_ms', '60000');

            mockFetch.mockResolvedValueOnce(new Response('not-json', { status: 200 }));

            const result = await manager.coalescedRefresh();

            expect(result).toBe(true);
            // Stored expiry is still present (setupRefreshTimer() read it back)
            expect(localStorage.getItem('auth_expires_at')).not.toBeNull();
        });

        it('does not reschedule timer when response lacks expires_in', async () => {
            mockFetch.mockResolvedValueOnce(jsonResponse({ some: 'data' }));

            const result = await manager.coalescedRefresh();

            expect(result).toBe(true);
            // setupRefreshTimer was never called — no expiry stored
            expect(localStorage.getItem('auth_expires_at')).toBeNull();
        });
    });

    // -----------------------------------------------------------------------
    // 7. doRefresh failure — clears timer, returns false
    // -----------------------------------------------------------------------
    describe('doRefresh failure', () => {
        it('returns false and clears localStorage on HTTP error', async () => {
            manager.setupRefreshTimer(300); // populate state

            mockFetch.mockResolvedValueOnce(new Response('', { status: 401 }));
            const result = await manager.coalescedRefresh();

            expect(result).toBe(false);
            expect(localStorage.getItem('auth_expires_at')).toBeNull();
            expect(localStorage.getItem('auth_lead_time_ms')).toBeNull();
        });

        it('returns false and clears localStorage on network error', async () => {
            manager.setupRefreshTimer(300);

            mockFetch.mockRejectedValueOnce(new Error('network failure'));
            const result = await manager.coalescedRefresh();

            expect(result).toBe(false);
            expect(localStorage.getItem('auth_expires_at')).toBeNull();
        });
    });

    // -----------------------------------------------------------------------
    // 8. isTokenFresh double-check after lock acquisition
    // -----------------------------------------------------------------------
    describe('proactiveRefresh with Web Locks', () => {
        it('skips refresh when token becomes fresh during lock acquisition', async () => {
            vi.setSystemTime(0);

            // Stale token: expires in 10s but lead time is 60s → clearly stale
            localStorage.setItem('auth_expires_at', '10000');
            localStorage.setItem('auth_lead_time_ms', '60000');

            // Mock navigator.locks — simulate another tab refreshing during lock wait
            vi.stubGlobal('navigator', {
                locks: {
                    request: vi.fn(
                        async (
                            _name: string,
                            _options: unknown,
                            callback: (lock: unknown) => Promise<void>
                        ) => {
                            // Another tab pushed the expiry forward before we got the lock
                            localStorage.setItem('auth_expires_at', String(Date.now() + 300_000));
                            await callback({}); // grant the lock
                        }
                    ),
                },
            });

            manager.setupRefreshTimer(); // delay <= 0 → immediate proactiveRefresh
            await vi.advanceTimersByTimeAsync(0);

            // Token was fresh by the time refreshIfStale ran — no fetch
            expect(mockFetch).not.toHaveBeenCalled();
        });
    });

    // -----------------------------------------------------------------------
    // clearRefreshTimer
    // -----------------------------------------------------------------------
    describe('clearRefreshTimer', () => {
        it('removes both localStorage keys', () => {
            manager.setupRefreshTimer(300);
            expect(localStorage.getItem('auth_expires_at')).not.toBeNull();

            manager.clearRefreshTimer();

            expect(localStorage.getItem('auth_expires_at')).toBeNull();
            expect(localStorage.getItem('auth_lead_time_ms')).toBeNull();
        });
    });

    // -----------------------------------------------------------------------
    // notifyAuthFailure
    // -----------------------------------------------------------------------
    describe('notifyAuthFailure', () => {
        it('invokes the registered callback', () => {
            const cb = vi.fn();
            manager.setAuthFailureCallback(cb);

            manager.notifyAuthFailure();

            expect(cb).toHaveBeenCalledOnce();
        });

        it('does not throw when no callback is registered', () => {
            expect(() => manager.notifyAuthFailure()).not.toThrow();
        });
    });

    // -----------------------------------------------------------------------
    // Auth middleware (via createAuthMiddleware)
    // -----------------------------------------------------------------------
    describe('authMiddleware', () => {
        let retryFetch: ReturnType<typeof vi.fn> & typeof fetch;
        let middleware: ReturnType<typeof createAuthMiddleware>;
        let authFailureCb: ReturnType<typeof vi.fn> & (() => void);

        beforeEach(() => {
            retryFetch = vi.fn() as ReturnType<typeof vi.fn> & typeof fetch;
            middleware = createAuthMiddleware(manager, retryFetch);
            authFailureCb = vi.fn() as ReturnType<typeof vi.fn> & (() => void);
            manager.setAuthFailureCallback(authFailureCb);
        });

        function callMiddleware(url: string, method: string, status: number) {
            const request = new Request(url, { method });
            const response = new Response('', { status });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return middleware.onResponse!({ request, response } as any);
        }

        it('passes through non-401 responses unchanged', async () => {
            const request = new Request('http://localhost/api/data', { method: 'GET' });
            const response = new Response('ok', { status: 200 });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = await middleware.onResponse!({ request, response } as any);

            expect(result).toBe(response);
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it('skips refresh for NO_REFRESH_PATHS', async () => {
            for (const path of ['/api/auth/login', '/api/auth/refresh', '/api/auth/logout']) {
                await callMiddleware(`http://localhost${path}`, 'POST', 401);
            }

            expect(mockFetch).not.toHaveBeenCalled();
            expect(authFailureCb).not.toHaveBeenCalled();
        });

        it('GET 401 → refresh succeeds → retries the request', async () => {
            mockFetch.mockResolvedValueOnce(jsonResponse({ expires_in: 300 }));
            const retryResponse = new Response('retried', { status: 200 });
            retryFetch.mockResolvedValueOnce(retryResponse);

            const request = new Request('http://localhost/api/data', { method: 'GET' });
            const original401 = new Response('', { status: 401 });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = await middleware.onResponse!({ request, response: original401 } as any);

            expect(mockFetch).toHaveBeenCalledOnce(); // refresh
            expect(retryFetch).toHaveBeenCalledOnce(); // retry
            expect(result).toBe(retryResponse); // retried response returned
            expect(authFailureCb).not.toHaveBeenCalled();
        });

        it('GET 401 → refresh fails → notifyAuthFailure, returns original response', async () => {
            mockFetch.mockResolvedValueOnce(new Response('', { status: 401 }));

            const request = new Request('http://localhost/api/data', { method: 'GET' });
            const original401 = new Response('', { status: 401 });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = await middleware.onResponse!({ request, response: original401 } as any);

            expect(mockFetch).toHaveBeenCalledOnce();
            expect(retryFetch).not.toHaveBeenCalled(); // no retry
            expect(result).toBe(original401);
            expect(authFailureCb).toHaveBeenCalledOnce();
        });

        it('POST 401 → refreshes token but does not retry the request', async () => {
            mockFetch.mockResolvedValueOnce(jsonResponse({ expires_in: 300 }));

            const request = new Request('http://localhost/api/data', { method: 'POST' });
            const original401 = new Response('', { status: 401 });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = await middleware.onResponse!({ request, response: original401 } as any);

            expect(mockFetch).toHaveBeenCalledOnce(); // refresh
            expect(retryFetch).not.toHaveBeenCalled(); // no retry for POST
            expect(result).toBe(original401); // original returned
            expect(authFailureCb).not.toHaveBeenCalled();
        });

        it('POST 401 → refresh fails → notifyAuthFailure', async () => {
            mockFetch.mockResolvedValueOnce(new Response('', { status: 401 }));

            const request = new Request('http://localhost/api/data', { method: 'POST' });
            const original401 = new Response('', { status: 401 });

            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = await middleware.onResponse!({ request, response: original401 } as any);

            expect(result).toBe(original401);
            expect(authFailureCb).toHaveBeenCalledOnce();
        });
    });
});
