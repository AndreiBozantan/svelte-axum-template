import type { UserInfo } from './generated/api';
import { AuthRefreshManager } from './auth-refresh-manager';

class AppStateDef {
    // counter which lets overlapping loads stack instead
    // starts at 1 for the app-boot load; App.svelte's onMount clears it.
    #loadingCount = $state<number>(1);
    isLoading = $derived(this.#loadingCount > 0);
    startLoading() {
        this.#loadingCount++;
    }
    stopLoading() {
        this.#loadingCount = Math.max(0, this.#loadingCount - 1);
    }

    activePage = $state<string>('about'); // Default to 'about'
    setActivePage(id: string, updateHistory = true) {
        this.activePage = id;
        if (updateHistory) {
            const path = id === 'welcome' ? '/' : `/${id}`;
            if (window.location.pathname !== path) {
                history.pushState(null, '', path);
            }
        }
    }

    intendedPage = $state<string | null>(null);
    setIntendedPage(page: string | null) {
        this.intendedPage = page;
    }

    user = $state<UserInfo | null>(null);
    userId = $state<number>(-1);
    isLoggedIn = $derived(this.user != null);
    isAdmin = $derived(this.user !== null && this.user.id === 1);
    setUser(user: UserInfo | null) {
        this.user = user;
        if (user === null) {
            AuthRefreshManager.instance.clearRefreshTimer();
        }
    }
}

export const AppState = new AppStateDef();

AuthRefreshManager.instance.setAuthFailureCallback(() => {
    AppState.setUser(null);
});
