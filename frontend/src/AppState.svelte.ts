import type { UserInfo } from '$lib/generated/api';
import { AuthRefreshManager } from '$lib/auth-refresh-manager';

// authenticated user plus the app-wide async activity indicator
class AppStateModel {
    user = $state<UserInfo | null>(null);
    isLoggedIn = $derived(this.user != null);
    isAdmin = $derived(this.user?.id === 0);

    setUser(user: UserInfo | null) {
        this.user = user;
        if (user === null) {
            AuthRefreshManager.instance.clearRefreshTimer();
        }
    }

    // counter so overlapping loads stack instead of racing; starts at 1 for the
    // app-boot load, which App.svelte clears once mounted
    #loadingCount = $state(1);
    isLoading = $derived(this.#loadingCount > 0);
    startLoading() {
        this.#loadingCount++;
    }
    stopLoading() {
        this.#loadingCount = Math.max(0, this.#loadingCount - 1);
    }
}

export const AppState = new AppStateModel();

AuthRefreshManager.instance.setAuthFailureCallback(() => {
    AppState.setUser(null);
});
