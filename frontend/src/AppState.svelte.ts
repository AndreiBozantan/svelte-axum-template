class AppState {
    user =  $state<string>('');
    isLoggedIn = $derived(this.user !== '' && this.user != null);
    isAdmin = $derived(this.user === 'admin');
    setUser(user: string) { this.user = user; }
    clearUser()  { this.user = ''; }

    isLoading = $state<boolean>(true);
    startLoading() { this.isLoading = true; }
    stopLoading() { this.isLoading = false; }
}

export const appState = new AppState();