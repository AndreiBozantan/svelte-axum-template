<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { getSession, postLogin, storeTokens } from "../ts/auth";
    import { onMount } from "svelte";

    let username = $state("");
    let password = $state("");
    let errorMessage = $state("");
    let successMessage = $state("");

    // Handle OAuth callback on page load
    onMount(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const oauthSuccess = urlParams.get('oauth_success');
        const accessToken = urlParams.get('access_token');
        const refreshToken = urlParams.get('refresh_token');

        if (oauthSuccess === 'true' && accessToken && refreshToken) {
            // Store the tokens
            storeTokens(accessToken, refreshToken);

            // Clear URL parameters for security
            window.history.replaceState({}, document.title, window.location.pathname);

            // Set success message and update app state
            successMessage = "Successfully signed in with Google!";
            appState.setUser("oauth_user"); // You might want to decode the token to get actual user info

            // Optionally, get the session to update user info
            getSession();
        }
    });

    async function handleLogin(): Promise<void> {
        let loginResponse = await postLogin(username, password);
        if (loginResponse.result == "error") {
            errorMessage = loginResponse.message;
        } else {
            getSession();
        }
    }
</script>

{#if appState.isLoggedIn}
    <div>
        <container>
            Logged in as: {appState.user} <br />
            Now you may access the <strong>secure area </strong>from the Nav above
        </container>
    </div>
{:else}
    {#if successMessage}
        <div class="success-message">
            {successMessage}
        </div>
    {/if}
    {#if errorMessage}
        <div class="error-message">
            {errorMessage}
        </div>
    {/if}
    <div>
        <container>
            <div>
                <label for="username">Username</label>
                <input
                    class="input"
                    type="username"
                    placeholder="username"
                    bind:value={username}
                />
                <label for="password">Password</label>
                <input
                    class="input"
                    type="password"
                    placeholder="password"
                    bind:value={password}
                />
                <button onclick={handleLogin}> Login </button>

                <!-- OAuth Login Section -->
                <div class="oauth-separator">
                    <span>or</span>
                </div>

                <button
                    class="google-signin-btn"
                    onclick={() => window.location.href = '/auth/oauth/google'}
                >
                    <svg class="google-icon" viewBox="0 0 24 24" width="18" height="18">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                    </svg>
                    Sign in with Google
                </button>
            </div>
        </container>
    </div>
{/if}

<style>
    div {
        margin: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    label {
        width: 210px;
        text-align: left;
    }

    .oauth-separator {
        margin: 20px 0;
        position: relative;
        text-align: center;
        width: 100%;
    }

    .oauth-separator::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 0;
        right: 0;
        height: 1px;
        background: #ddd;
    }

    .oauth-separator span {
        background: white;
        padding: 0 15px;
        color: #666;
        font-size: 14px;
    }

    .google-signin-btn {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        padding: 12px 24px;
        border: 1px solid #dadce0;
        border-radius: 4px;
        background: white;
        color: #3c4043;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
        min-width: 210px;
    }

    .google-signin-btn:hover {
        box-shadow: 0 1px 2px 0 rgba(60,64,67,.30), 0 1px 3px 1px rgba(60,64,67,.15);
        background: #f8f9fa;
    }

    .google-signin-btn:active {
        background: #f1f3f4;
    }

    .google-icon {
        width: 18px;
        height: 18px;
    }

    .success-message {
        padding: 12px;
        background: #d4edda;
        color: #155724;
        border: 1px solid #c3e6cb;
        border-radius: 4px;
        margin-bottom: 20px;
        width: 210px;
        text-align: center;
    }

    .error-message {
        padding: 12px;
        background: #f8d7da;
        color: #721c24;
        border: 1px solid #f1aeb5;
        border-radius: 4px;
        margin-bottom: 20px;
        width: 210px;
        text-align: center;
    }
</style>
