import { appState } from '../AppState.svelte';

export interface User {
    id: number;
    email: string;
    tenant_id: number;
}

export interface AuthResponse {
    result: 'ok' | 'error';
    user?: User;
    message?: string;
}

export async function getSession(): Promise<AuthResponse> {
    try {
        const res = await fetch('/api/auth/session', { credentials: 'same-origin' });
        const data = await res.json();
        if (data.result === 'ok' && data.user) {
            appState.setUser(data.user.email);
        } else {
            appState.clearUser();
        }
        return data;
    } catch (error) {
        console.error('Failed to get session:', error);
        appState.clearUser();
        return { result: 'error', message: 'Network error' };
    }
}

export async function postLogin(email: string, password: string): Promise<AuthResponse> {
    const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (data.result === 'ok' && data.user) {
        appState.setUser(data.user.email);
    }
    return data;
}

export async function getLogout(): Promise<AuthResponse> {
    const res = await fetch("/api/auth/logout", { credentials: 'same-origin' });
    const data = await res.json();
    if (data.result === 'ok') {
        appState.clearUser();
        clearTokens();
    }
    return data;
}

// OAuth token storage and management (not strictly needed with cookies but good for manual API calls)
export function storeTokens(accessToken: string, refreshToken: string) {
    localStorage.setItem('access_token', accessToken);
    localStorage.setItem('refresh_token', refreshToken);
}

export function getAccessToken(): string | null {
    return localStorage.getItem('access_token');
}

export function getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token');
}

export function clearTokens() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
}
