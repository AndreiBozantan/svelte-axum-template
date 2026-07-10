<script lang="ts">
    import { onMount } from 'svelte';
    import { AppState } from '$lib/AppState.svelte';
    import { Pages, resolveRedirect } from './AppPages.svelte';
    import AppSidebar from './AppSidebar.svelte';

    const pageMap = Object.fromEntries(Pages.map((item) => [item.id, item]));
    const CurrentPage = $derived(pageMap[AppState.activePage]);

    onMount(() => {
        AppState.stopLoading();

        // keep the active page in sync with browser back/forward
        window.addEventListener('popstate', () => {
            AppState.setActivePage(window.location.pathname, false);
        });
    });

    // routing guards: bounce anonymous users off protected pages (remembering the
    // destination) and send logged-in users away from anonymous-only pages
    $effect(() => {
        const target = resolveRedirect(
            AppState.activePage,
            AppState.isLoggedIn,
            AppState.intendedPage
        );
        if (target === null) return;
        AppState.setIntendedPage(target === 'login' ? AppState.activePage : null);
        AppState.setActivePage(target);
    });
</script>

<div class="app-layout">
    <AppSidebar />

    <main class="content">
        {#if CurrentPage}
            <CurrentPage.component />
        {/if}
    </main>
</div>

<style>
    :global(body) {
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background-color: #fffaf5;
        color: #1e293b;
    }

    .app-layout {
        display: flex;
        min-height: 100vh;
    }

    .content {
        flex: 1;
        display: flex;
        flex-direction: column;
        overflow-y: auto;
        margin-left: 72px; /* Narrow sidebar width */
    }

    @media only screen and (max-width: 768px) {
        .app-layout {
            flex-direction: column;
        }
        .content {
            margin-left: 0;
        }
    }
</style>
