<script lang="ts">
    import { AppState } from '$src/AppState.svelte';
    import { api } from '$lib/api';

    let response = $state('');

    async function handleApiCheck(): Promise<void> {
        response = '';
        const { data, error } = await api.users.user_info();
        if (error) {
            response = `Error: ${error.message}`;
        } else {
            response = JSON.stringify(data, null, 2);
        }
    }
</script>

<div class="page">
    <div class="content-container">
        <!-- Page Header Group -->
        <div class="page-header-block">
            <h1 class="page-main-header">secure api check</h1>
            <p class="header-desc">
                This page demonstrates how to make a secure, authenticated request to the backend
                API.
            </p>
        </div>

        <!-- API Action Group -->
        <div class="section-block">
            <div class="section-header">
                <h2>Protected API Endpoint</h2>
                <p class="">
                    Click the button to call a protected API endpoint that requires authentication.
                </p>
            </div>
            <div>
                <button class="btn-primary" onclick={handleApiCheck} disabled={AppState.isLoading}>
                    {AppState.isLoading ? 'Calling API...' : 'Call Protected API endpoint'}
                </button>

                {#if response}
                    <div class="response-container">
                        <div class="info-label">Backend Response:</div>
                        <pre class="response-box">{response}</pre>
                    </div>
                {/if}
            </div>
        </div>
    </div>
</div>

<style>
    /* Local specialized styles */
    .response-container {
        margin-top: 24px;
    }
    .response-box {
        background: #f1f5f9;
        padding: 16px;
        border-radius: 8px;
        font-family: ui-monospace, monospace;
        font-size: 0.85rem;
        color: #334155;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
        margin-top: 12px;
        display: block;
    }
</style>
