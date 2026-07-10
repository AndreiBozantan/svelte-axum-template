import './app.css';

import { mount } from 'svelte';

import { api } from '$lib/api';
import { AppState } from './AppState.svelte';
import { AuthRefreshManager } from '$lib/auth-refresh-manager';
import type { UserInfo } from '$lib/generated/api';

import App from './App.svelte';

async function bootstrap() {
    try {
        const user = await fetchUser();
        AppState.setUser(user);

        const target = document.getElementById('app');
        if (!target) {
            throw new Error('Target element #app not found in the DOM.');
        }

        return mount(App, { target });
    } catch (error) {
        console.error('Bootstrap failed:', error);
        renderFallbackUI(document.getElementById('app'));
    }
}

function renderFallbackUI(target: HTMLElement | null): void {
    if (!target) return;
    target.innerHTML = `
        <div style="font-family: sans-serif; padding: 2rem; text-align: center; color: #e11d48; max-width: 500px; margin: 4rem auto; border: 1px solid #fec2c2; background-color: #fff5f5; border-radius: 8px;">
            <h1 style="font-size: 1.5rem; margin-bottom: 0.5rem;">Failed to load application</h1>
            <p style="color: #475569; font-size: 0.95rem; margin-bottom: 1.5rem;">An unexpected error occurred during bootstrap. Please refresh or try again later.</p>
        </div>
    `;
}

function getCookie(name: string): string | null {
    // ensure that we have a semicolon before first cookie also and search cookie
    // by name including a start semicolon to avoid partial name matches
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop()?.split(';').shift() ?? null;
    }
    return null;
}

function clearLoginCookie(): void {
    document.cookie =
        'logged_in=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Secure';
}

async function fetchUser(): Promise<UserInfo | null> {
    const isLoggedIn = getCookie('logged_in') === 'true';
    if (!isLoggedIn) return null;

    try {
        const { data, error } = await api.users.user_info();
        if (error) {
            // 401 is expected (not logged in); anything else is worth knowing about
            if (error.code !== 'not_authenticated') {
                console.warn('getUserInfo failed:', error);
            }
            clearLoginCookie();
            return null;
        }

        if (data) {
            if (typeof data.expires_in === 'number') {
                AuthRefreshManager.instance.setupRefreshTimer(data.expires_in);
            }
            return data.user;
        }
    } catch (apiError) {
        console.error('Failed to fetch user info during bootstrap:', apiError);
        clearLoginCookie();
    }
    return null;
}

bootstrap();
