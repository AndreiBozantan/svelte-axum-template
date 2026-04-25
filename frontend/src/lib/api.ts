import type { AuthResponse } from './types';

class Api {
    private async handleResponse(res: Response): Promise<any> {
        const contentType = res.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
            return await res.json();
        } else {
            const text = await res.text();
            try {
                // try to parse as JSON anyway, in case content-type is missing
                return JSON.parse(text);
            } catch {
                // return as an object with the text as message
                return { result: res.ok ? "ok" : "error", message: text || res.statusText };
            }
        }
    }

    async getTest(api_token?: string): Promise<any> {
        const headers: Record<string, string> = {
            "Accept": "application/json",
        };

        if (api_token) {
            headers["Authorization"] = "Bearer " + api_token;
        }

        const options: RequestInit = { headers };
        if (!api_token) {
            options.credentials = 'same-origin';
        }

        const res = await fetch('/api/test', options);
        return await this.handleResponse(res);
    }

    async getHealth(): Promise<any> {
        const res = await fetch('/api/health');
        return await this.handleResponse(res);
    }

    // Auth methods
    async getUserInfo(): Promise<AuthResponse> {
        const res = await fetch('/api/auth/user_info', { credentials: 'same-origin' });
        return await this.handleResponse(res);
    }

    async login(email: string, password: string): Promise<AuthResponse> {
        const res = await fetch("/api/auth/login", {
            method: "POST",
            headers: {
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ email, password }),
        });
        return await this.handleResponse(res);
    }

    async logout(): Promise<AuthResponse> {
        const res = await fetch("/api/auth/logout", { credentials: 'same-origin' });
        return await this.handleResponse(res);
    }
}

export const api = new Api();
