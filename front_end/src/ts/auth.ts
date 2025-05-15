import { appState } from '../AppState.svelte';

// Token storage
const ACCESS_TOKEN_KEY = 'access_token';
const REFRESH_TOKEN_KEY = 'refresh_token';
const TOKEN_EXPIRY_KEY = 'token_expiry';

// Helper to store tokens
function storeTokens(accessToken: string, refreshToken: string | null, expiresIn: number) {
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    
    if (refreshToken) {
        localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    }
    
    const expiryTime = Date.now() + (expiresIn * 1000); // Convert seconds to milliseconds
    localStorage.setItem(TOKEN_EXPIRY_KEY, expiryTime.toString());
}

// Helper to clear tokens
function clearTokens() {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(TOKEN_EXPIRY_KEY);
}

// Get access token, refreshing if needed
export async function getAccessToken(): Promise<string | null> {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    const expiryStr = localStorage.getItem(TOKEN_EXPIRY_KEY);
    
    if (!token || !expiryStr) {
        return null;
    }
    
    const expiry = parseInt(expiryStr, 10);
    
    // Check if token is expired or about to expire (within 1 minute)
    if (Date.now() > expiry - 60000) {
        // Try to refresh the token
        const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
        if (refreshToken) {
            try {
                const refreshResult = await refreshAuthToken(refreshToken);
                if (refreshResult.result === 'ok') {
                    return refreshResult.access_token;
                }
            } catch (error) {
                clearTokens();
                return null;
            }
        } else {
            clearTokens();
            return null;
        }
    }
    
    return token;
}

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
    
    const response = await res.json();
    
    if (response.result === 'ok' && response.access_token) {
        // Store the tokens
        storeTokens(
            response.access_token, 
            response.refresh_token || null, 
            response.expires_in
        );
    }
    
    return response;
}

export async function refreshAuthToken(refreshToken: string) {
    const res = await fetch('/auth/token/refresh', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh_token: refreshToken }),
    });
    
    const response = await res.json();
    
    if (response.result === 'ok' && response.access_token) {
        // Store the new tokens
        storeTokens(
            response.access_token, 
            response.refresh_token || null, 
            response.expires_in
        );
    }
    
    return response;
}

export async function getLogout() {
    // First, get the refresh token to revoke it on the server
    const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY);
    
    if (refreshToken) {
        try {
            // Call the revoke token endpoint
            await fetch('/auth/token/revoke', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });
        } catch (error) {
            console.error('Failed to revoke token:', error);
        }
    }
    
    // Also invalidate the session
    const res = await fetch("/auth/logout", {credentials: 'same-origin'});
    const logoutResponse = await res.json();
    
    // Clear tokens from local storage
    clearTokens();
    
    if (logoutResponse.result === "error") {
        // may want to return an error here
    } else {
        appState.clearUser();
    }
    
    return logoutResponse;
}