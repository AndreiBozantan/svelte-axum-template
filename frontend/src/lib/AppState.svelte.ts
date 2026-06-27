import type { UserInfo } from './generated/api';

class AppStateDef {
    isLoading = $state<boolean>(true);
    startLoading() {
        this.isLoading = true;
    }
    stopLoading() {
        this.isLoading = false;
    }

    activePage = $state<string>('about'); // Default to 'about'
    setActivePage(id: string) {
        this.activePage = id;
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
    }
}

export const AppState = new AppStateDef();
