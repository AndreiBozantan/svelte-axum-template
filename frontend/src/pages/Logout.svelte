<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { api } from "../lib/api";
    import { onMount } from "svelte";

    onMount(async () => {
        const res = await api.logout();
        appState.setAuth(res);
    });
</script>

<div>
    <div class="logout-container">
        {#if appState.isLoggedIn}
            You are still logged in as {appState.user}.
        {:else}
            You are now logged out.
        {/if}
    </div>
</div>

<style>
    div {
        margin: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }

    .logout-container {
        width: 300px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        padding: 20px;
        border-radius: 8px;
        background: white;
    }
</style>
