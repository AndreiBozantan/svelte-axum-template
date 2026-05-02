import './app.css'
import App from './App.svelte'
import { mount } from 'svelte'
import { appState } from './AppState.svelte'
import { api } from './lib/api'

async function bootstrap() {
    try {
        // Try to get the initial user_info data (user, theme, etc.)
        // This is preloaded in index.html for maximum performance
        const userInfoPath = "/user_info.js"; // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_username
        const { initialUserInfo } = await import(/* @vite-ignore */ userInfoPath)
            .catch(() => ({ initialUserInfo: null })) as any;

        const userInfo = (initialUserInfo?.result === 'ok' && initialUserInfo.user) 
            ? initialUserInfo 
            : await api.getUserInfo();
        
        appState.setAuth(userInfo);
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
