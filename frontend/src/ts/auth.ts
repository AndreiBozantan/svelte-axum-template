import { appState } from '../AppState.svelte';

export async function getSession() {
    const res = await fetch('/auth/session',{credentials: 'same-origin'});
    let sessionResponse = await res.json();
    appState.setUser(sessionResponse.user_id);
}

export async function postLogin(username: string, password: string) {
    const res = await fetch("/auth/login", {
        method: "POST",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ username: username, password: password }),
    });
    return await res.json();
}

export async function getLogout() {
    const res = await fetch("/auth/logout", {credentials: 'same-origin'});

    let logoutResponse = await res.json();
    if (logoutResponse.result == "error") {
        // may want to return an error here
    } else {
        appState.clearUser();
    }
}