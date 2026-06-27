/**
 * Encapsulates token-refresh state to allow:
 * 1. Isolated unit testing (avoiding global state pollution).
 * 2. Clean state teardown on logout (clearing active timers/promises).
 * 3. Support for multiple independent API clients with separate auth sessions.
 */
export class AuthRefreshManager {
    public static readonly instance = new AuthRefreshManager();

    private refreshPromise: Promise<boolean> | null = null;
    private refreshTimer: ReturnType<typeof setTimeout> | null = null;
    private onAuthFailure: (() => void) | null = null;
    private readonly fetchFn: typeof fetch;

    constructor(fetchFn: typeof fetch = globalThis.fetch) {
        this.fetchFn = fetchFn;
    }

    setAuthFailureCallback(cb: () => void) {
        this.onAuthFailure = cb;
    }

    /** Notify the auth-failure callback exactly once. Callers decide when. */
    notifyAuthFailure() {
        this.onAuthFailure?.();
    }

    /**
     * Coalesce concurrent refresh calls into a single in-flight request.
     * Does NOT call onAuthFailure — that responsibility belongs to the caller
     * so it is invoked exactly once per failure scenario.
     *
     * Note on ??= semantics: doRefresh() clears this.refreshPromise in its
     * finally block before awaiting callers resume. A caller arriving after
     * finally but before earlier awaiters resume will start a new refresh —
     * this is correct behavior (the previous token is already consumed).
     */
    async coalescedRefresh(): Promise<boolean> {
        this.refreshPromise ??= this.doRefresh();
        return this.refreshPromise;
    }

    private async doRefresh(): Promise<boolean> {
        try {
            const r = await this.fetchFn('/api/auth/refresh', {
                method: 'POST',
                credentials: 'same-origin',
            });

            if (!r.ok) {
                this.clearRefreshTimer();
                return false;
            }

            try {
                const data = await r.json();
                if (data && typeof data.expires_in === 'number') {
                    this.setupRefreshTimer(data.expires_in);
                }
            } catch (e) {
                console.error('Failed to parse refresh response json', e);
                // fall back to any stored expiry so the timer is not silently lost
                this.setupRefreshTimer();
            }

            return true;
        } catch (err) {
            console.error('Token refresh request failed', err);
            this.clearRefreshTimer();
            return false;
        } finally {
            this.refreshPromise = null;
        }
    }

    setupRefreshTimer(expiresInSeconds?: number) {
        this.clearTimer();

        const resolved = this.resolveRefreshParams(expiresInSeconds);
        if (!resolved) return;

        const { expiresAt, leadTime } = resolved;

        // add up to 5 seconds of random jitter to stagger timers across tabs
        const jitter = Math.random() * 5_000;
        const delay = expiresAt - Date.now() - leadTime - jitter;

        if (delay <= 0) {
            // already past lead time — refresh immediately using standard proactive check/lock path
            void this.proactiveRefresh(leadTime);
            return;
        }

        this.refreshTimer = setTimeout(() => this.proactiveRefresh(leadTime), delay);
    }

    clearRefreshTimer() {
        this.clearTimer();
        localStorage.removeItem('auth_expires_at');
        localStorage.removeItem('auth_lead_time_ms');
    }

    private clearTimer() {
        if (this.refreshTimer) {
            clearTimeout(this.refreshTimer);
            this.refreshTimer = null;
        }
    }

    /** Persist or read refresh timing params from localStorage. */
    private resolveRefreshParams(
        expiresInSeconds?: number
    ): { expiresAt: number; leadTime: number } | null {
        if (expiresInSeconds !== undefined) {
            const expiresAt = Date.now() + expiresInSeconds * 1000;
            const leadTime = expiresInSeconds < 120 ? 15_000 : 60_000;
            localStorage.setItem('auth_expires_at', expiresAt.toString());
            localStorage.setItem('auth_lead_time_ms', leadTime.toString());
            return { expiresAt, leadTime };
        }

        const storedExpiry = localStorage.getItem('auth_expires_at');
        if (!storedExpiry) return null;

        const expiresAt = parseInt(storedExpiry, 10);
        if (isNaN(expiresAt)) return null;

        const storedLead = localStorage.getItem('auth_lead_time_ms');
        const leadTime = storedLead ? parseInt(storedLead, 10) : 60_000;
        return { expiresAt, leadTime };
    }

    /**
     * Check whether another tab already refreshed the token, then call
     * coalescedRefresh() under the Web Locks API when available.
     */
    private async proactiveRefresh(leadTime: number) {
        // if another tab already refreshed (expiry pushed out), just reschedule
        if (this.isTokenFresh(leadTime)) {
            this.setupRefreshTimer();
            return;
        }

        const refresh = () => this.refreshIfStale(leadTime);

        if (!this.hasWebLocks()) {
            // no Web Locks API — refresh directly (single-tab fallback)
            await refresh();
            return;
        }

        await this.withRefreshLock(refresh);
    }

    /** True when the stored expiry is still far enough in the future. */
    private isTokenFresh(leadTime: number): boolean {
        const stored = localStorage.getItem('auth_expires_at');
        const expiresAt = stored ? parseInt(stored, 10) : 0;
        return expiresAt > Date.now() + leadTime;
    }

    private hasWebLocks(): boolean {
        return typeof navigator !== 'undefined' && !!navigator.locks;
    }

    /**
     * Acquire the cross-tab refresh lock without blocking and run `task`
     * while the lock is held. Reschedules the timer when the lock is
     * unavailable or the API throws.
     */
    private async withRefreshLock(task: () => Promise<void>) {
        try {
            await navigator.locks.request(
                'auth_refresh_lock',
                { ifAvailable: true },
                async (lock) => {
                    if (!lock) {
                        // another tab holds the lock — reschedule
                        this.setupRefreshTimer();
                        return;
                    }
                    await task();
                }
            );
        } catch (err) {
            // lock API failure — reschedule instead of bypassing the lock
            console.error('Web lock request failed, rescheduling refresh', err);
            this.setupRefreshTimer();
        }
    }

    /**
     * Re-check freshness (another tab may have finished between our initial
     * check and lock acquisition) and refresh if still stale.
     *
     * Deliberately no notifyAuthFailure() — the proactive path runs before the
     * user triggers a request, so redirecting to login unprompted would be
     * jarring. The next actual API call will 401, hit the middleware, and
     * notify then.
     */
    private async refreshIfStale(leadTime: number) {
        if (this.isTokenFresh(leadTime)) {
            this.setupRefreshTimer();
            return;
        }

        console.log('Proactively refreshing access token...');
        const ok = await this.coalescedRefresh();
        if (!ok) console.warn('Proactive token refresh failed.');
    }
}

// ---------------------------------------------------------------------------
// Cross-tab sync & visibility handlers
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined') {
    window.addEventListener('storage', (e) => {
        // guard against key deletion (e.g. clearRefreshTimer) which fires with
        // newValue === null — setupRefreshTimer would no-op but this avoids
        // the redundant round-trip through resolveExpiresAt
        if (e.key === 'auth_expires_at' && e.newValue !== null) {
            AuthRefreshManager.instance.setupRefreshTimer();
        }
    });

    window.addEventListener('focus', () => {
        // only reschedule when the user is authenticated (has a stored expiry)
        if (localStorage.getItem('auth_expires_at')) {
            AuthRefreshManager.instance.setupRefreshTimer();
        }
    });
}
