import createClient from 'openapi-fetch';
import type { Middleware } from 'openapi-fetch';
import type { paths } from './generated/api';

let refreshPromise: Promise<boolean> | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;
let onAuthFailure: (() => void) | null = null;

// paths where a 401 should not trigger a refresh attempt.
const NO_REFRESH_PATHS = new Set(['/api/auth/login', '/api/auth/refresh']);

export function setAuthFailureCallback(cb: () => void) {
    onAuthFailure = cb;
}

const authMiddleware: Middleware = {
    async onResponse({ request, response }) {
        if (response.status !== 401) return response;

        const url = new URL(request.url);
        if (NO_REFRESH_PATHS.has(url.pathname)) return response;

        // only retry GET requests transparently; for POST/PUT/PATCH, let the
        // call site handle it since request bodies cannot be easily re-read/retried
        if (request.method !== 'GET') return response;

        const refreshed = await coalescedRefresh();
        if (!refreshed) {
            if (onAuthFailure) onAuthFailure();
            return response;
        }

        // retry the original GET request once
        return fetch(request);
    },
};

export async function coalescedRefresh(): Promise<boolean> {
    if (!refreshPromise) {
        // if there is no active refresh request in flight, initiate one
        refreshPromise = (async () => {
            try {
                const r = await fetch('/api/auth/refresh', {
                    method: 'POST',
                    credentials: 'same-origin',
                });
                if (r.ok) {
                    try {
                        const data = await r.json();
                        if (data && typeof data.expires_in === 'number') {
                            setupRefreshTimer(data.expires_in);
                        }
                    } catch (e) {
                        console.error('Failed to parse refresh response json', e);
                    }
                    return true;
                }
                clearRefreshTimer();
                if (onAuthFailure) onAuthFailure();
                return false;
            } catch (err) {
                console.error('Token refresh request failed', err);
                clearRefreshTimer();
                if (onAuthFailure) onAuthFailure();
                return false;
            } finally {
                // clear the promise reference once completed (on success or failure)
                // so that subsequent 401s in the future can trigger a new refresh flow.
                refreshPromise = null;
            }
        })();
    }
    // return the active refresh promise so that
    // multiple concurrent 401s will await this same promise
    return refreshPromise;
}

export function setupRefreshTimer(expiresInSeconds?: number) {
    if (refreshTimer) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
    }

    let expiresAt: number | null = null;
    if (expiresInSeconds !== undefined) {
        expiresAt = Date.now() + expiresInSeconds * 1000;
        localStorage.setItem('auth_expires_at', expiresAt.toString());
    } else {
        const stored = localStorage.getItem('auth_expires_at');
        if (stored) {
            expiresAt = parseInt(stored, 10);
        }
    }

    if (!expiresAt || isNaN(expiresAt)) {
        return;
    }

    // Refresh proactive e.g. 60 seconds before expiration
    // If expires_in is very short (e.g. under 2 minutes), refresh 15 seconds before.
    const leadTime = expiresInSeconds !== undefined && expiresInSeconds < 120 ? 15000 : 60000;
    // Add up to 5 seconds of random jitter to stagger timers across tabs
    const jitter = Math.random() * 5000;
    const delay = expiresAt - Date.now() - leadTime - jitter;

    if (delay > 0) {
        refreshTimer = setTimeout(async () => {
            const runRefreshWithLock = async () => {
                const currentStored = localStorage.getItem('auth_expires_at');
                const currentExpiresAt = currentStored ? parseInt(currentStored, 10) : 0;
                if (currentExpiresAt > Date.now() + leadTime) {
                    // Another tab refreshed it, reschedule timer
                    setupRefreshTimer();
                    return;
                }

                console.log('Proactively refreshing access token...');
                const success = await coalescedRefresh();
                if (!success) {
                    console.warn('Proactive token refresh failed.');
                }
            };

            // Use Web Locks API if supported by the browser to prevent concurrent refresh requests
            if (typeof navigator !== 'undefined' && navigator.locks) {
                try {
                    await navigator.locks.request(
                        'auth_refresh_lock',
                        { ifAvailable: true },
                        async (lock) => {
                            if (!lock) {
                                // Lock not available: another tab is already refreshing.
                                // Reschedule the timer to check status later.
                                setupRefreshTimer();
                                return;
                            }
                            await runRefreshWithLock();
                        }
                    );
                } catch (err) {
                    console.error('Web lock request failed, falling back to direct refresh', err);
                    await runRefreshWithLock();
                }
            } else {
                await runRefreshWithLock();
            }
        }, delay);
    } else {
        // If expired or past lead time, refresh immediately
        coalescedRefresh();
    }
}

export function clearRefreshTimer() {
    if (refreshTimer) {
        clearTimeout(refreshTimer);
        refreshTimer = null;
    }
    localStorage.removeItem('auth_expires_at');
}

if (typeof window !== 'undefined') {
    window.addEventListener('storage', (e) => {
        if (e.key === 'auth_expires_at') {
            setupRefreshTimer();
        }
    });

    window.addEventListener('focus', () => {
        setupRefreshTimer();
    });
}

export const api = createClient<paths>({
    credentials: 'same-origin',
});
api.use(authMiddleware);
