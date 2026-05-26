import type { User } from './types';
 
export class ApiError extends Error {
    readonly code: string;
    constructor(code: string, message: string) {
        super(message);
        this.code = code;
        this.name = 'ApiError';
    }
}

export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    limit: number;
    offset: number;
}

export interface PaginationParams {
    limit?: number;
    offset?: number;
}

class Api {
    constructor(private readonly baseUrl = '') {}

    // ---- core helpers ----

    private jsonHeaders(): Record<string, string> {
        return { Accept: 'application/json', 'Content-Type': 'application/json' };
    }

    private buildUrl(path: string, params?: Record<string, unknown>): string {
        const url = new URL(this.baseUrl + path, window.location.origin);
        if (params) {
            for (const [key, value] of Object.entries(params)) {
                if (value !== undefined && value !== null) {
                    url.searchParams.set(key, String(value));
                }
            }
        }
        return url.pathname + url.search;
    }

    private async handleResponse<T>(res: Response): Promise<T> {
        if (res.status === 204) return undefined as T;
        const contentType = res.headers.get('content-type');
        let data: unknown;
        if (contentType?.includes('application/json')) {
            data = await res.json();
        } else {
            const text = await res.text();
            try { data = JSON.parse(text); }
            catch {
                if (!res.ok) throw new ApiError('error', text || res.statusText);
                return text as T;
            }
        }
        if (!res.ok) {
            const err = data as Record<string, string>;
            throw new ApiError(err.code ?? 'error', err.message ?? res.statusText);
        }
        return data as T;
    }

    private async get<T>(
        path: string,
        params?: Record<string, unknown>,
        signal?: AbortSignal,
    ): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.buildUrl(path, params), {
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    private async post<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.baseUrl + path, {
            method: 'POST',
            headers: this.jsonHeaders(),
            body: JSON.stringify(body),
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    private async postEmpty<T>(path: string, signal?: AbortSignal): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.baseUrl + path, {
            method: 'POST',
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    private async put<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.baseUrl + path, {
            method: 'PUT',
            headers: this.jsonHeaders(),
            body: JSON.stringify(body),
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    private async patch<T>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.baseUrl + path, {
            method: 'PATCH',
            headers: this.jsonHeaders(),
            body: JSON.stringify(body),
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    private async del<T>(path: string, signal?: AbortSignal): Promise<T> {
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch(this.baseUrl + path, {
            method: 'DELETE',
            credentials: 'same-origin',
            signal,
        });
        return this.handleResponse(res);
    }

    // ---- auth ----

    async login(email: string, password: string, signal?: AbortSignal): Promise<{ user: User }> {
        return this.post('/api/auth/login', { email, password }, signal);
    }

    async logout(signal?: AbortSignal): Promise<void> {
        return this.postEmpty('/api/auth/logout', signal);
    }

    // ---- users ----

    async getUserInfo(signal?: AbortSignal): Promise<{ user: User }> {
        return this.get('/api/users/me', undefined, signal);  // was /api/auth/user_info
    }

    async getUsers(
        { limit = 50, offset = 0 }: PaginationParams = {},
        signal?: AbortSignal,
    ): Promise<PaginatedResponse<User>> {
        const raw = await this.get<{
            users: User[];
            total: number;
            limit: number;
            offset: number;
        }>('/api/users', { limit, offset }, signal);

        // normalise to a consistent shape regardless of backend field name
        return { items: raw.users, total: raw.total, limit: raw.limit, offset: raw.offset };
    }

    // ---- misc ----

    async getHealth(signal?: AbortSignal): Promise<{ message: string }> {
        return this.get('/api/health', undefined, signal);
    }
}

export const api = new Api();