<script lang="ts">
    import { onMount } from "svelte";
    import { getApi } from "../ts/fetch";
    import { getAccessToken } from "../ts/auth";

    let token = $state("");
    let response = $state("");
    
    // Load the token from storage when component mounts
    onMount(async () => {
        const savedToken = await getAccessToken();
        if (savedToken) {
            token = savedToken;
        }
    });    async function handlebutton(): Promise<void> {
        response = "<nothing returned>";
        try {
            // Use the provided token or get from storage if empty
            const tokenToUse = token.trim() || await getAccessToken() || undefined;
            response = JSON.stringify(await getApi(tokenToUse));
            console.log(`TOKEN: ${tokenToUse}`);
            console.log(`RESPONSE: ${response}`);
        } catch (error) {
            response = `Error: ${error.message}`;
        }
    }
    
    async function refreshToken(): Promise<void> {
        try {
            // Get refresh token from localStorage
            const refreshToken = localStorage.getItem('refresh_token');
            if (!refreshToken) {
                response = "No refresh token available. Please log in first.";
                return;
            }
            
            // Call the token refresh endpoint
            const res = await fetch('/auth/token/refresh', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ refresh_token: refreshToken }),
            });
            
            const refreshResponse = await res.json();
            
            if (refreshResponse.result === 'ok') {
                // Update the displayed token
                token = refreshResponse.access_token;
                response = "Token refreshed successfully";
            } else {
                response = `Failed to refresh token: ${refreshResponse.message}`;
            }
        } catch (error) {
            response = `Error refreshing token: ${error.message}`;
        }
    }
</script>

<div>
    <container class="wider mobile">
        <p>
            You can try using the default API to access api of backend server or
            you can try entering a bad token to see what happens. This can be
            used with or without logging in.
        </p>        <label for="apiToken">API Token</label>
        <input class="input" type="text" bind:value={token} />
        <button onclick={handlebutton}> Get /api </button>
        <button onclick={refreshToken}> Refresh Token </button>

        <p class="mono">RESPONSE: {response}</p>
    </container>
</div>

<style>
    div {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin: 25px;
    }

    @media only screen and (max-width: 620px) {
        container.mobile {
            width: 300px;
        }
    }
</style>
