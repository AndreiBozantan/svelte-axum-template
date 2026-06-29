import createClient from 'openapi-fetch';
import type { Middleware } from 'openapi-fetch';
import type { paths } from './generated/api';
import { AuthRefreshManager } from './auth-refresh-manager';

export const fetchClient = createClient<paths>({
    credentials: 'same-origin',
});

const errorHandlingMiddleware: Middleware = {
    onError({ error }) {
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
