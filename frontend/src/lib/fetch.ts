import createClient from 'openapi-fetch';
import type { Middleware } from 'openapi-fetch';
import type { paths } from './generated/api';
import { AppState } from './AppState.svelte';
import { AuthRefreshManager } from './auth-refresh-manager';

export const fetchClient = createClient<paths>({
    credentials: 'same-origin',
});

const errorHandlingMiddleware: Middleware = {
    onError({ error: _error }) {
        return new Response(
            JSON.stringify({
                code: 'NETWORK_ERROR',
                message: 'An unexpected error occurred. Please try again.',
            }),
            {
                status: 500,
                headers: { 'Content-Type': 'application/json' },
            }
        );
    },
};

fetchClient.use(errorHandlingMiddleware);
fetchClient.use(createAuthMiddleware(AuthRefreshManager.instance));

// Drives the app-wide loading indicator for every request, so callers don't
// need to call AppState.startLoading()/stopLoading() themselves.
// Wraps the HTTP methods instead of using onRequest/onResponse middleware:
// openapi-fetch skips onResponse if any onRequest throws, which would leak
// startLoading() with no matching stopLoading().
// try/finally can't leak like that - it always runs, even if fn() throws.
function withLoadingIndicator<T extends (...args: never[]) => Promise<unknown>>(fn: T): T {
    return (async (...args: Parameters<T>) => {
        AppState.startLoading();
        try {
            return await fn(...args);
        } finally {
            AppState.stopLoading();
        }
    }) as T;
}

for (const method of [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'PATCH',
    'OPTIONS',
    'HEAD',
    'TRACE',
] as const) {
    fetchClient[method] = withLoadingIndicator(fetchClient[method].bind(fetchClient));
}

// paths where a 401 should not trigger a refresh attempt
const NO_REFRESH_PATHS = new Set(['/api/auth/login', '/api/auth/refresh', '/api/auth/logout']);

export function createAuthMiddleware(
    manager: AuthRefreshManager,
    retryFetch: typeof fetch = globalThis.fetch
): Middleware {
    return {
        async onResponse({ request, response }) {
            if (response.status !== 401) return response;

            const url = new URL(request.url);
            if (NO_REFRESH_PATHS.has(url.pathname)) return response;

            // for non-GET requests we can't transparently retry (body already
            // consumed), but we still refresh the token so subsequent calls succeed
            if (request.method !== 'GET') {
                const refreshed = await manager.coalescedRefresh();
                if (!refreshed) manager.notifyAuthFailure();
                return response;
            }

            // GET — attempt refresh, then retry once
            const refreshed = await manager.coalescedRefresh();
            if (!refreshed) {
                manager.notifyAuthFailure();
                return response;
            }

            return retryFetch(request);
        },
    };
}
