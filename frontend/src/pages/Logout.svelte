<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { getLogout } from "../ts/auth";
    import { onMount } from "svelte";

    onMount(getLogout);
</script>

<div>
    <container>
        {#if appState.isLoggedIn}
            You are still logged in as {appState.user}.
        {:else}
            You are now logged out.
        {/if}
    </container>
</div>

<style>
    div {
        margin: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }
</style>
