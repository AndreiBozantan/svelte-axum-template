import type { UserInfo } from './generated/api';
import { AuthRefreshManager } from './auth-refresh-manager';
import { router, push } from 'svelte-spa-router';

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

    // derived from the router's hash location so it always reflects the current route
    activePage = $derived(router.location.slice(1));
    setActivePage(route: string) {
        const id = route.startsWith('/') ? route.slice(1) : route;
        push(`/${id}`);
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
