export type SidebarMode = 'hover' | 'pinned' | 'locked';

class AppState {
    user =  $state<string>('');
    isLoggedIn = $derived(this.user !== '' && this.user != null);
    isAdmin = $derived(this.user === 'admin');
    setUser(user: string) { this.user = user; }
    clearUser()  { this.user = ''; }

    activeMenu = $state<number>(1); // Default to MENU_ID.ABOUT (1)
    setActiveMenu(id: number) { this.activeMenu = id; }

    isLoading = $state<boolean>(true);
    startLoading() { this.isLoading = true; }
    stopLoading() { this.isLoading = false; }

    sidebarMode = $state<SidebarMode>('locked');
    cycleSidebarMode() {
        if (this.sidebarMode === 'hover') this.sidebarMode = 'pinned';
        else if (this.sidebarMode === 'pinned') this.sidebarMode = 'locked';
        else this.sidebarMode = 'hover';
    }
}

export const appState = new AppState();