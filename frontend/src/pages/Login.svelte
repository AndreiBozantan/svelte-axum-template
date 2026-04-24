<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { getSession, postLogin } from "../lib/auth";
    import { onMount, tick } from "svelte";
    import { MENU_ID } from "../lib/constants";

    let email = $state("");
    let password = $state("");
    let errorMessage = $state("");
    let isLoading = $state(false);
    let emailInput: HTMLInputElement | undefined = $state();

    onMount(async () => {
        if (!appState.isLoggedIn) {
            await tick();
            emailInput?.focus();
        }
    });

    async function handleLogin(e: Event): Promise<void> {
        e.preventDefault();
        errorMessage = "";
        isLoading = true;
        try {
            const loginResponse = await postLogin(email, password);
            if (loginResponse.result === "error") {
                errorMessage = loginResponse.message || "Invalid credentials";
            } else {
                // User info is already updated in appState by postLogin
                // but we can call getSession to be sure
                await getSession();
            }
        } catch (error) {
            errorMessage = "An unexpected error occurred. Please try again.";
        } finally {
            isLoading = false;
        }
    }

    function handleGoogleLogin() {
        // Save the current menu ID so we can return here after SSO redirect
        sessionStorage.setItem("return_menu_id", MENU_ID.LOGIN.toString());
        const redirectUrl = encodeURIComponent(window.location.origin);
        window.location.href = `/api/auth/oauth/google?redirect_url=${redirectUrl}`;
    }
</script>

<div class="login-container">
    {#if appState.isLoggedIn}
        <div class="card logged-in">
            <h2>Welcome Back!</h2>
            <p>You are logged in as <strong>{appState.user}</strong></p>
            <div class="success-banner">
                <svg viewBox="0 0 24 24" width="24" height="24">
                    <path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                </svg>
                <span>Authentication Successful</span>
            </div>
            <div class="quick-links">
                <p class="hint">Quick Links:</p>
                <div class="links-grid">
                    <button class="btn-link" onclick={() => appState.setActiveMenu(MENU_ID.ABOUT)}>About</button>
                    <button class="btn-link" onclick={() => appState.setActiveMenu(MENU_ID.SETTINGS)}>Settings</button>
                    <button class="btn-link" onclick={() => appState.setActiveMenu(MENU_ID.SECURE)}>Secure Area</button>
                    <button class="btn-link logout" onclick={() => appState.setActiveMenu(MENU_ID.LOGOUT)}>Logout</button>
                </div>
            </div>
        </div>
    {:else}
        <div class="card">
            <h1>Sign In</h1>
            <p class="subtitle">Access your account to continue</p>

            {#if errorMessage}
                <div class="error-alert">
                    <svg viewBox="0 0 24 24" width="20" height="20">
                        <path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/>
                    </svg>
                    <span>{errorMessage}</span>
                </div>
            {/if}

            <form onsubmit={handleLogin}>
                <div class="form-group">
                    <label for="email">Email Address</label>
                    <input
                        id="email"
                        bind:this={emailInput}
                        type="email"
                        placeholder="name@company.com"
                        bind:value={email}
                        required
                        autocomplete="email"
                    />
                </div>

                <div class="form-group">
                    <div class="label-row">
                        <label for="password">Password</label>
                    </div>
                    <input
                        id="password"
                        type="password"
                        placeholder="••••••••"
                        bind:value={password}
                        required
                        autocomplete="current-password"
                    />
                </div>

                <button type="submit" class="btn-primary" disabled={isLoading}>
                    {#if isLoading}
                        <span class="spinner"></span>
                        Signing in...
                    {:else}
                        Sign In
                    {/if}
                </button>
            </form>

            <div class="divider">
                <span>or continue with</span>
            </div>

            <button class="btn-google" onclick={handleGoogleLogin}>
                <svg class="google-icon" viewBox="0 0 24 24" width="20" height="20">
                    <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Google
            </button>
        </div>
    {/if}
</div>

<style>
    .login-container {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 60vh;
        padding: 20px;
    }

    .card {
        background: white;
        padding: 40px;
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.05);
        width: 100%;
        max-width: 400px;
        text-align: center;
    }

    h1 {
        margin: 0 0 10px 0;
        font-size: 24px;
        color: #1a1a1a;
    }

    h2 {
        margin: 0 0 15px 0;
        color: #1a1a1a;
    }

    .subtitle {
        color: #666;
        margin-bottom: 30px;
        font-size: 15px;
    }

    .form-group {
        text-align: left;
        margin-bottom: 20px;
    }

    .label-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    label {
        display: block;
        font-size: 14px;
        font-weight: 500;
        margin-bottom: 8px;
        color: #333;
    }

    input {
        width: 100%;
        padding: 12px 16px;
        border: 1px solid #ddd;
        border-radius: 8px;
        font-size: 15px;
        transition: border-color 0.2s, box-shadow 0.2s;
        box-sizing: border-box;
    }

    input:focus {
        outline: none;
        border-color: #10b981;
        box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
    }

    .btn-primary {
        width: 100%;
        padding: 12px;
        background: #10b981;
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
    }

    .btn-primary:hover:not(:disabled) {
        background: #059669;
    }

    .btn-primary:disabled {
        opacity: 0.7;
        cursor: not-allowed;
    }

    .divider {
        margin: 25px 0;
        position: relative;
        text-align: center;
    }

    .divider::before {
        content: '';
        position: absolute;
        top: 50%;
        left: 0;
        right: 0;
        height: 1px;
        background: #eee;
    }

    .divider span {
        background: white;
        padding: 0 15px;
        color: #999;
        font-size: 13px;
        position: relative;
    }

    .btn-google {
        width: 100%;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 12px;
        padding: 12px;
        border: 1px solid #ddd;
        border-radius: 8px;
        background: white;
        color: #333;
        font-size: 15px;
        font-weight: 500;
        cursor: pointer;
        transition: background 0.2s, border-color 0.2s;
    }

    .btn-google:hover {
        background: #f9f9f9;
        border-color: #ccc;
    }

    .error-alert {
        display: flex;
        align-items: center;
        gap: 10px;
        background: #fff5f5;
        color: #c53030;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 20px;
        font-size: 14px;
        text-align: left;
        border: 1px solid #feb2b2;
    }

    .success-banner {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        background: #ecfdf5;
        color: #065f46;
        padding: 12px;
        border-radius: 8px;
        margin: 20px 0;
        font-weight: 500;
        border: 1px solid #d1fae5;
    }

    .hint {
        color: #64748b;
        font-size: 14px;
    }

    .quick-links {
        margin-top: 25px;
        padding-top: 20px;
        border-top: 1px solid #eee;
    }

    .links-grid {
        display: grid;
        grid-template-columns: repeat(2, 1fr);
        gap: 12px;
        margin-top: 15px;
    }

    .btn-link {
        padding: 10px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        color: #475569;
        font-size: 14px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s;
    }

    .btn-link:hover {
        background: #f1f5f9;
        border-color: #cbd5e1;
        color: #0f172a;
    }

    .btn-link.logout {
        color: #ef4444;
    }

    .btn-link.logout:hover {
        background: #fef2f2;
        border-color: #fecaca;
    }

    .spinner {
        width: 18px;
        height: 18px;
        border: 2px solid rgba(255, 255, 255, 0.3);
        border-top-color: white;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
        to { transform: rotate(360deg); }
    }

    .logged-in {
        animation: fadeIn 0.5s ease-out;
    }

    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
</style>
