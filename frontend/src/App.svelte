<script lang="ts">
    import { onMount } from 'svelte';
    import Router, { push } from 'svelte-spa-router';
    import type { RouteDetail } from 'svelte-spa-router';
    import { AppState } from '$lib/AppState.svelte';
    import { routes } from './AppPages.svelte';
    import AppSidebar from './AppSidebar.svelte';

    onMount(() => {
        if (window.location.pathname !== '/') {
            const cleanUrl = '/' + window.location.hash;
            window.history.replaceState(null, '', cleanUrl);
        }
        AppState.stopLoading();
    });

    function handleConditionsFailed(detail: RouteDetail) {
        if (AppState.isLoggedIn) {
            // logged-in user hit an anonymous-only route (e.g. /login) -> send them home
            push('/');
        } else {
            // anonymous user hit a protected route -> remember it and bounce to login
            AppState.setIntendedPage(detail.location);
            push('/login');
        }
    }

    // once login completes while sitting on the Login page, go to the originally intended page
    $effect(() => {
        if (AppState.isLoggedIn && AppState.activePage === 'login') {
            const target = AppState.intendedPage || '';
            AppState.setIntendedPage(null);
            AppState.setActivePage(target);
        }
    });
</script>

<div class="app-layout">
    <AppSidebar />

    <main class="content">
        <Router {routes} onConditionsFailed={handleConditionsFailed} />
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
