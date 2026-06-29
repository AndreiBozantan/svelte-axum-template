import './app.css';

import { mount } from 'svelte';

import { api } from '$lib/api';
import { AppState } from '$lib/AppState.svelte';
import { AuthRefreshManager } from '$lib/auth-refresh-manager';

import App from './App.svelte';

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

async function bootstrap() {
    try {
        const isLoggedIn = getCookie('logged_in') === 'true';
        let user = null;

        if (isLoggedIn) {
            const { data, error } = await api.users.user_info();
            if (error) {
                // 401 is expected (not logged in); anything else is worth knowing about
                if (error.code !== 'not_authenticated') console.warn('getUserInfo failed:', error);
                // clear client-side indicator since auth failed
                document.cookie =
                    'logged_in=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax; Secure';
            } else if (data) {
                user = data.user;
                if (typeof data.expires_in === 'number') {
                    AuthRefreshManager.instance.setupRefreshTimer(data.expires_in);
                }
            }
        }

        AppState.setUser(user);

        const target = document.getElementById('app');
        if (!target) {
            throw new Error('Target element #app not found in the DOM.');
        }

        return mount(App, { target });
    } catch (error) {
        console.error('Bootstrap failed:', error);
    }
}

bootstrap();
