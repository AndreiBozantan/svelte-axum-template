<script lang="ts">
    import { onMount } from 'svelte';
    import { Router } from './Router.svelte';
    import { AppState } from './AppState.svelte';
    import AppSidebar from './AppSidebar.svelte';
    import NotFound from './pages/NotFound.svelte';

    // derived redirect target
    const redirectTarget = $derived(Router.getRedirectTarget(AppState.isLoggedIn));

    // get the page component definition for the active route
    const currentPage = $derived(Router.getPageById(Router.activePage));

    onMount(() => {
        AppState.stopLoading();

        // keep the active page in sync with browser back/forward
        window.addEventListener('popstate', () => {
            Router.setActivePage(window.location.pathname, false);
        });
    });

    // routing guards: bounce anonymous users off protected pages (remembering the destination)
    // and send logged-in users away from anonymous-only pages
    $effect(() => {
        if (redirectTarget === null) return;
        // remember where an anonymous user was headed; clear it once they're back in
        Router.setIntendedPage(AppState.isLoggedIn ? null : Router.activePage);
        Router.setActivePage(redirectTarget);
    });
</script>

<div class="app-layout">
    <AppSidebar />

    <main class="content">
        <!-- while a redirect is pending, render nothing so guarded pages never mount -->
        {#if redirectTarget === null}
            {#if currentPage}
                <currentPage.component />
            {:else}
                <NotFound />
            {/if}
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
