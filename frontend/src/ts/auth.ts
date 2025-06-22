import { appState } from '../AppState.svelte';

export async function getSession() {
    const res = await fetch('/auth/session',{credentials: 'same-origin'});
    let sessionResponse = await res.json();
    appState.setUser(sessionResponse.user_id);
}

export async function postLogin(username: string, password: string) {
    const res = await fetch("/auth/login", {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: username, password: password }),
    });
    return await res.json();
}

// OAuth token storage and management
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

export async function getLogout() {
    const res = await fetch("/auth/logout", {credentials: 'same-origin'});

    let logoutResponse = await res.json();
    if (logoutResponse.result == "error") {
        // may want to return an error here
    } else {
        appState.clearUser();
        clearTokens(); // Clear OAuth tokens as well
    }
}