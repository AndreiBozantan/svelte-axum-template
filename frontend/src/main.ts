import './app.css'

import { mount } from 'svelte'
import { AppState } from './AppState.svelte'
import { api } from './lib/api'

import App from './App.svelte'

async function bootstrap() {
    try {
        const user = await api.getUserInfo()
            .then(r => r.user)
            .catch((err) => {
                // 401 is expected (not logged in); anything else is worth knowing about
                if (err.code !== 'not_authenticated') console.warn('getUserInfo failed:', err);
                return null;
            });

        AppState.setUser(user);

        const target = document.getElementById('app');
        if (!target) {
            throw new Error("Target element #app not found in the DOM.");
        }

        return mount(App, { target });
    } catch (error) {
        console.error("Bootstrap failed:", error);
    }
}

bootstrap();
