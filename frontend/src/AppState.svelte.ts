import type { AuthResponse } from './lib/types';

class AppStateDef {
    isLoading = $state<boolean>(true);
    startLoading() { this.isLoading = true; }
    stopLoading() { this.isLoading = false; }

    activePage = $state<string>('about'); // Default to 'about'
    setActivePage(id: string) { this.activePage = id; }

    intendedPage = $state<string | null>(null);
    setIntendedPage(page: string | null) { this.intendedPage = page; }

    user =  $state<string>('');
    userId = $state<number>(-1);
    isLoggedIn = $derived(this.user !== '' && this.user != null);
    isAdmin = $derived(this.userId === 1);
    setUser(user: string) { this.user = user; }
    clearUser()  { this.user = ''; this.userId = -1; }

    /**
     * Updates the application authentication state from an AuthResponse.
     * Returns true if the user is authenticated, false otherwise.
     */
    setAuth(data: AuthResponse): boolean {
        if (data.result === 'ok' && data.user) {
            this.user = data.user.email;
            this.userId = data.user.id;
            return true;
        }
        this.user = '';
        this.userId = -1;
        return false;
    }
}

export const AppState = new AppStateDef();
