import createClient from 'openapi-fetch';
import type { Middleware } from 'openapi-fetch';
import type { paths } from './generated/api';
import { AppState } from './AppState.svelte';

let refreshPromise: Promise<boolean> | null = null;

// paths where a 401 should not trigger a refresh attempt.
const NO_REFRESH_PATHS = new Set(['/api/auth/login', '/api/auth/refresh']);

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
            AppState.setUser(null);
            return response;
        }

        // retry the original GET request once
        return fetch(request);
    },
};

async function coalescedRefresh(): Promise<boolean> {
    if (!refreshPromise) {
        // if there is no active refresh request in flight, initiate one
        refreshPromise = (async () => {
            try {
                const r = await fetch('/api/auth/refresh', {
                    method: 'POST',
                    credentials: 'same-origin',
                });
                return r.ok;
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

export const api = createClient<paths>({
    credentials: 'same-origin',
});
api.use(authMiddleware);
