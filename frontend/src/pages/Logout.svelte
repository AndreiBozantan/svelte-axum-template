<script lang="ts">
    import { AppState } from '$lib/AppState.svelte';
    import { api } from '$lib/api';
    import type { ApiError } from '$lib/api';
    import { onMount } from 'svelte';
    import { Fa } from 'svelte-fa';
    import {
        faCheckCircle,
        faExclamationTriangle,
        faSignInAlt,
        faHome,
        faRedo,
    } from '@fortawesome/free-solid-svg-icons';

    let hasAttempted = $state(false);
    let errorMessage = $state('');

    async function handleLogout() {
        if (!AppState.isLoggedIn) {
            hasAttempted = true;
            return;
        }

        errorMessage = '';
        const { error } = await api.auth.logout();

        if (error) {
            const apiError = error as ApiError;
            errorMessage = apiError.message || 'An unexpected error occurred during logout.';
        } else {
            AppState.setUser(null);
        }
        hasAttempted = true;
    }

    onMount(() => {
        handleLogout();
    });

    function navigateToLogin() {
        AppState.setActivePage('login');
    }

    function navigateToHome() {
        AppState.setActivePage('welcome');
    }
</script>

<div class="logout-page">
    <div class="card">
        {#if AppState.isLoading || !hasAttempted}
            <div class="status-container">
                <div class="spinner-wrapper">
                    <span class="spinner"></span>
                </div>
                <h2>Logging out...</h2>
                <p class="subtitle">Securely closing your session. Please wait.</p>
            </div>
        {:else if errorMessage}
            <div class="status-container">
                <div class="icon-wrapper error">
                    <Fa icon={faExclamationTriangle} size="3x" />
                </div>
                <h2>Logout Failed</h2>
                <p class="subtitle">
                    We encountered an issue while trying to log you out. You are still logged in as <strong
                        class="user-email">{AppState.user?.email}</strong
                    >.
                </p>

                <div class="error-alert">
                    <span>{errorMessage}</span>
                </div>

                <div class="button-group">
                    <button class="btn-primary" onclick={handleLogout}>
                        <Fa icon={faRedo} /> Try Again
                    </button>
                    <button class="btn-secondary" onclick={navigateToHome}> Return to App </button>
                </div>
            </div>
        {:else}
            <div class="status-container">
                <div class="icon-wrapper success">
                    <Fa icon={faCheckCircle} size="3x" />
                </div>
                <h2>You're all set!</h2>
                <p class="subtitle">You have successfully logged out of your session.</p>

                <div class="button-group">
                    <button class="btn-primary" onclick={navigateToLogin}>
                        <Fa icon={faSignInAlt} /> Sign In Again
                    </button>
                    <button class="btn-secondary" onclick={navigateToHome}>
                        <Fa icon={faHome} /> Go to Home
                    </button>
                </div>
            </div>
        {/if}
    </div>
</div>

<style>
    .logout-page {
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
        max-width: 420px;
        text-align: center;
        border: 1px solid rgba(226, 232, 240, 0.8);
    }

    .status-container {
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    h2 {
        margin: 20px 0 10px 0;
        font-size: 22px;
        color: #1e293b;
        font-weight: 600;
    }

    .subtitle {
        color: #64748b;
        margin-bottom: 24px;
        font-size: 15px;
        line-height: 1.5;
    }

    .user-email {
        color: #0f172a;
        word-break: break-all;
    }

    .spinner-wrapper {
        margin-bottom: 10px;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 60px;
    }

    .spinner {
        display: inline-block;
        width: 40px;
        height: 40px;
        border: 3px solid rgba(16, 185, 129, 0.2);
        border-top-color: #10b981;
        border-radius: 50%;
        animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
        to {
            transform: rotate(360deg);
        }
    }

    .icon-wrapper {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 80px;
        height: 80px;
        border-radius: 50%;
        margin-bottom: 10px;
    }

    .icon-wrapper.success {
        background-color: #ecfdf5;
        color: #10b981;
    }

    .icon-wrapper.error {
        background-color: #fef2f2;
        color: #ef4444;
    }

    .error-alert {
        width: 100%;
        background: #fef2f2;
        color: #b91c1c;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 24px;
        font-size: 14px;
        text-align: left;
        border: 1px solid #fee2e2;
        box-sizing: border-box;
    }

    .button-group {
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 100%;
    }

    .btn-primary {
        width: 100%;
        padding: 12px;
        background: #10b981;
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 8px;
        transition: all 0.2s ease;
        box-shadow: 0 4px 6px -1px rgba(16, 185, 129, 0.2);
    }

    .btn-primary:hover {
        background: #059669;
        transform: translateY(-1px);
        box-shadow: 0 6px 8px -1px rgba(16, 185, 129, 0.3);
    }

    .btn-primary:active {
        transform: translateY(0);
    }

    .btn-secondary {
        width: 100%;
        padding: 12px;
        background: #f8fafc;
        color: #475569;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 8px;
        transition: all 0.2s ease;
    }

    .btn-secondary:hover {
        background: #f1f5f9;
        color: #1e293b;
        border-color: #cbd5e1;
    }
</style>
