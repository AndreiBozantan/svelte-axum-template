import './app.css'

import { mount } from 'svelte'
import { AppState } from './AppState.svelte'
import { api } from './lib/api'
import type { User } from './lib/types';

import App from './App.svelte'

async function bootstrap() {
    try {
        // Try to get the initial user_info data (user, theme, etc.)
        // This is preloaded in index.html for maximum performance
        const userInfoPath = "/user_info.js"; // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_username
        const { initialUserInfo } = await import(/* @vite-ignore */ userInfoPath)
            .catch(() => ({ initialUserInfo: null })) as any;

        // initialUserInfo from /user_info.js is a raw User object or null (no envelope)
        // api.getUserInfo() returns { user: User } — unwrap accordingly
        const user = initialUserInfo?.email
            ? initialUserInfo as User
            : await api.getUserInfo().then(r => r.user).catch(() => null);

        AppState.setAuth(user);
    } catch (error) {
        console.error("Bootstrap failed:", error);
    }

    const targetElement = document.getElementById('app');
    if (!targetElement) {
        throw new Error("Target element #app not found in the DOM.");
    }

    return mount(App, {
        target: targetElement
    });
}

const app = bootstrap();

export default app
