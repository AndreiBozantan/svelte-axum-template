<script lang="ts">
    import { onMount } from "svelte";
    import { AppState } from "./AppState.svelte";
    import { Pages } from "./AppPages.svelte";
    import AppSidebar from "./AppSidebar.svelte";

    const pageMap = Object.fromEntries(Pages.map((item) => [item.id, item]));
    const getActivePage = () => pageMap[AppState.activePage];

    onMount(async () => {
        // await new Promise((resolve) => setTimeout(resolve, 900));

        AppState.stopLoading();

        // Set initial page from URL
        const path = window.location.pathname;
        let initialPage = 'welcome';
        if (path === '/') initialPage = 'welcome';
        else if (path.startsWith('/')) initialPage = path.slice(1);
        AppState.setActivePage(initialPage);

        // Listen to browser back/forward
        window.addEventListener('popstate', () => {
            const currentPath = window.location.pathname;
            let page = 'welcome';
            if (currentPath === '/') page = 'welcome';
            else page = currentPath.slice(1);
            AppState.setActivePage(page);
        });
    });


    // Auto-redirect logic
    $effect(() => {
        const active = getActivePage();
        
        // If logged out and on a protected page, redirect to login
        if (active && !active.public && !AppState.isLoggedIn) {
            AppState.setIntendedPage(AppState.activePage);
            history.pushState(null, '', '/login');
            AppState.setActivePage('login');
        }
        
        // If just logged in and on Login page, go to Welcome
        if (AppState.isLoggedIn && AppState.activePage === 'login') {
            const target = AppState.intendedPage || 'welcome';
            history.pushState(null, '', '/' + (target === 'welcome' ? '' : target));
            AppState.setActivePage(target);
            AppState.setIntendedPage(null);
        }
    });

    const CurrentPage = $derived(getActivePage());
</script>

<div class="app-layout">
    <AppSidebar />

    <main class="content">
        {#if CurrentPage}
            <CurrentPage.component />
        {:else}
            <div class="page">
                <h2>Page Not Found (ID: {AppState.activePage})</h2>
            </div>
        {/if}
    </main>
</div>

<style>
    :global(body) {
        margin: 0;
        padding: 0;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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
