// name of the cross-tab Web Locks lock guarding token refresh
const REFRESH_LOCK_NAME = 'auth_refresh_lock';

// localStorage fallback lock (used when the Web Locks API is unavailable);
// the TTL bounds both how long a crashed tab can hold the lock and how long a waiter polls
const FALLBACK_LOCK_KEY = 'auth_refresh_in_progress';
const FALLBACK_LOCK_TTL_MS = 10_000;
const FALLBACK_LOCK_POLL_MS = 200;
const FALLBACK_LOCK_SETTLE_MS = 50;

// retry delay when another tab holds the refresh lock during a proactive refresh
const LOCK_RETRY_DELAY_MS = 5_000;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

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
     * Coalesce concurrent refresh calls into a single in-flight request,
     * serialized against other tabs via the cross-tab lock.
     * Does NOT call onAuthFailure — that responsibility belongs to the caller
     * so it is invoked exactly once per failure scenario.
     */
    async coalescedRefresh(leadTime?: number): Promise<boolean> {
        return this.coalesced(() => this.refreshUnderCrossTabLock(leadTime));
    }

    /**
     * Dedup concurrent refresh calls in this tab into one in-flight promise.
     *
     * Note: the finally below clears refreshPromise before earlier awaiters
     * resume. A caller arriving after finally but before earlier awaiters
     * resume will start a new refresh — this is correct behavior (the
     * previous token is already consumed).
     */
    private async coalesced(refresh: () => Promise<boolean>): Promise<boolean> {
        if (this.refreshPromise) {
            return this.refreshPromise;
        }
        this.refreshPromise = refresh();
        try {
            return await this.refreshPromise;
        } finally {
            this.refreshPromise = null;
        }
    }

    /** acquire the cross-tab lock (Web Locks or localStorage fallback), then refresh. */
    private async refreshUnderCrossTabLock(leadTime?: number): Promise<boolean> {
        const initialExpiry = localStorage.getItem('auth_expires_at');
        if (!this.hasWebLocks()) {
            return this.refreshWithLocalStorageLock(initialExpiry, leadTime);
        }
        return navigator.locks.request(REFRESH_LOCK_NAME, () =>
            this.refreshUnlessRedundant(initialExpiry, leadTime)
        );
    }

    /**
     * Post-lock double check shared by both lock strategies: skip the network
     * call when the expiry changed (another tab refreshed while we waited) or,
     * when a leadTime is given, the token is currently fresh.
     */
    private async refreshUnlessRedundant(
        initialExpiry: string | null,
        leadTime?: number
    ): Promise<boolean> {
        if (localStorage.getItem('auth_expires_at') !== initialExpiry) {
            return true;
        }
        if (leadTime !== undefined && this.isTokenFresh(leadTime)) {
            return true;
        }
        return this.doRefresh();
    }

    private async refreshWithLocalStorageLock(
        initialExpiry: string | null,
        leadTime?: number
    ): Promise<boolean> {
        const startTime = Date.now();

        while (Date.now() - startTime < FALLBACK_LOCK_TTL_MS) {
            const activeLock = localStorage.getItem(FALLBACK_LOCK_KEY);
            const lockTime = activeLock ? parseInt(activeLock, 10) : 0;
            const isLockHeld = activeLock !== null && Date.now() - lockTime < FALLBACK_LOCK_TTL_MS;

            if (!isLockHeld) {
                // try to acquire the lock, then sleep to let concurrent writes settle
                const myToken = Date.now().toString();
                localStorage.setItem(FALLBACK_LOCK_KEY, myToken);
                await sleep(FALLBACK_LOCK_SETTLE_MS);

                if (localStorage.getItem(FALLBACK_LOCK_KEY) === myToken) {
                    try {
                        return await this.refreshUnlessRedundant(initialExpiry, leadTime);
                    } finally {
                        localStorage.removeItem(FALLBACK_LOCK_KEY);
                    }
                }
            }

            // lock is held by another tab — wait, then check whether it refreshed
            await sleep(FALLBACK_LOCK_POLL_MS);
            if (localStorage.getItem('auth_expires_at') !== initialExpiry) {
                return true;
            }
        }

        // timeout fallback — refresh anyway so the tab doesn't hang forever
        return this.doRefresh();
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
     * Check whether another tab already refreshed the token, then refresh
     * under the cross-tab lock. On the Web Locks path the lock is acquired
     * here (non-blocking), so the refresh task must not re-acquire it.
     */
    private async proactiveRefresh(leadTime: number) {
        // if another tab already refreshed (expiry pushed out), just reschedule
        if (this.isTokenFresh(leadTime)) {
            this.setupRefreshTimer();
            return;
        }

        if (!this.hasWebLocks()) {
            // no Web Locks API — coalescedRefresh serializes via the localStorage lock
            await this.refreshIfStale(leadTime, () => this.coalescedRefresh(leadTime));
            return;
        }

        // the lock is already held inside the task — only coalesce within this tab
        await this.withRefreshLock(leadTime, () =>
            this.refreshIfStale(leadTime, () => this.coalesced(() => this.doRefresh()))
        );
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

    private scheduleRetry(leadTime: number) {
        this.clearTimer();
        this.refreshTimer = setTimeout(() => this.proactiveRefresh(leadTime), LOCK_RETRY_DELAY_MS);
    }

    /**
     * Acquire the cross-tab refresh lock without blocking and run `task`
     * while the lock is held. Reschedules the timer when the lock is
     * unavailable or the API throws.
     */
    private async withRefreshLock(leadTime: number, task: () => Promise<void>) {
        try {
            await navigator.locks.request(
                REFRESH_LOCK_NAME,
                { ifAvailable: true },
                async (lock) => {
                    if (!lock) {
                        // another tab holds the lock — reschedule with retry delay
                        this.scheduleRetry(leadTime);
                        return;
                    }
                    await task();
                }
            );
        } catch (err) {
            // lock API failure — reschedule with retry delay instead of bypassing the lock
            console.error('Web lock request failed, rescheduling refresh', err);
            this.scheduleRetry(leadTime);
        }
    }

    /**
     * Re-check freshness (another tab may have finished between our initial
     * check and lock acquisition) and run `refresh` if still stale.
     *
     * Deliberately no notifyAuthFailure() — the proactive path runs before the
     * user triggers a request, so redirecting to login unprompted would be
     * jarring. The next actual API call will 401, hit the middleware, and
     * notify then.
     */
    private async refreshIfStale(leadTime: number, refresh: () => Promise<boolean>) {
        if (this.isTokenFresh(leadTime)) {
            this.setupRefreshTimer();
            return;
        }

        console.log('Proactively refreshing access token...');
        const ok = await refresh();
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
