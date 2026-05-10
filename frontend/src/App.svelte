<script lang="ts">
    import { appState } from "./AppState.svelte";
    import Sidebar from "./components/Sidebar.svelte";
    import About from "./pages/About.svelte";
    import Welcome from "./pages/Welcome.svelte";
    import LogIn from "./pages/Login.svelte";
    import LogOut from "./pages/Logout.svelte";
    import SecureApi from "./pages/SecureApi.svelte";
    import Settings from "./pages/Settings.svelte";
    import { onMount } from "svelte";

    onMount(async () => {
        // await new Promise((resolve) => setTimeout(resolve, 900));

        appState.stopLoading();

        // Set initial page from URL
        const path = window.location.pathname;
        let initialPage = 'welcome';
        if (path === '/') initialPage = 'welcome';
        else if (path.startsWith('/')) initialPage = path.slice(1);
        appState.setActivePage(initialPage);

        // Listen to browser back/forward
        window.addEventListener('popstate', () => {
            const currentPath = window.location.pathname;
            let page = 'welcome';
            if (currentPath === '/') page = 'welcome';
            else page = currentPath.slice(1);
            appState.setActivePage(page);
        });
    });

    // Simple mapping of string IDs to components
    const pageMap: Record<string, any> = {
        'welcome': { component: Welcome, public: false },
        'secure': { component: SecureApi, public: false },
        'about': { component: About, public: true },
        'settings': { component: Settings, public: false },
        'login': { component: LogIn, public: true },
        'logout': { component: LogOut, public: false },
    };

    // Auto-redirect logic
    $effect(() => {
        const active = pageMap[appState.activePage];
        
        // If logged out and on a protected page, go to About
        if (active && !active.public && !appState.isLoggedIn) {
            history.pushState(null, '', '/about');
            appState.setActivePage('about');
        }
        
        // If just logged in and on Login page, go to Welcome
        if (appState.isLoggedIn && appState.activePage === 'login') {
            history.pushState(null, '', '/');
            appState.setActivePage('welcome');
        }
    });

    const CurrentPage = $derived(pageMap[appState.activePage]);
</script>

<div class="app-layout">
    <Sidebar />

    <main class="content">
        {#if CurrentPage}
            <CurrentPage.component />
        {:else}
            <div class="page">
                <h2>Page Not Found (ID: {appState.activePage})</h2>
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
