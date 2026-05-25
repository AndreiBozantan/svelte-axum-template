import type { User } from './types';

export class ApiError extends Error {
    readonly code: string;
    constructor(code: string, message: string) {
        super(message);
        this.code = code;
        this.name = 'ApiError';
    }
}

class Api {
    private async handleResponse<T>(res: Response): Promise<T> {
        if (res.status === 204) return undefined as T;

        const contentType = res.headers.get("content-type");
        let data: any;

        if (contentType?.includes("application/json")) {
            data = await res.json();
        } else {
            const text = await res.text();
            try { data = JSON.parse(text); }
            catch {
                if (!res.ok) throw new ApiError('error', text || res.statusText);
                return text as any;
            }
        }

        if (!res.ok) {
            throw new ApiError(data.code ?? 'error', data.message ?? res.statusText);
        }
        return data as T;
    }

    async getTest(api_token?: string): Promise<{ message: string }> {
        const headers: Record<string, string> = { "Accept": "application/json" };
        if (api_token) headers["Authorization"] = "Bearer " + api_token;

        const options: RequestInit = { headers };
        if (!api_token) options.credentials = 'same-origin';

        const res = await fetch('/api/test', options);
        return this.handleResponse(res);
    }

    async getHealth(): Promise<{ message: string }> {
        const res = await fetch('/api/health');
        return this.handleResponse(res);
    }

    async getUserInfo(): Promise<{ user: User }> {
        const res = await fetch('/api/auth/user_info', { credentials: 'same-origin' });
        return this.handleResponse(res);
    }

    async login(email: string, password: string): Promise<{ user: User }> {
        const options: RequestInit = {
            method: "POST",
            credentials: 'same-origin',
            headers: { "Accept": "application/json", "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        };
        // semgrep rule is flagging this as potential SSRF, due to the email and string input in the body. 
        // nosemgrep: gitlab.nodejs_scan.javascript-ssrf-rule-node_ssrf
        const res = await fetch("/api/auth/login", options); 
        return this.handleResponse(res);
    }

    async logout(): Promise<void> {
        const options: RequestInit = {
            method: "POST",
            credentials: 'same-origin'
        };
        const res = await fetch("/api/auth/logout", options);
        return this.handleResponse(res);
    }
}

export const api = new Api();