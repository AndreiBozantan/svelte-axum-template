<script lang="ts">
    import { getSession } from "./lib/auth";
    import { appState } from "./AppState.svelte";
    import Sidebar from "./component/Sidebar.svelte";
    import About from "./pages/About.svelte";
    import LogIn from "./pages/Login.svelte";
    import LogOut from "./pages/Logout.svelte";
    import Secure from "./pages/Secure.svelte";
    import Apicheck from "./pages/Apicheck.svelte";
    import Settings from "./pages/Settings.svelte";
    import { onMount } from "svelte";
    import { faInfoCircle, faShieldAlt, faCheckCircle, faCog, faSignInAlt, faUser } from '@fortawesome/free-solid-svg-icons';
    import { MENU_ID } from "./lib/constants";

    // check if logged in
    onMount(async () => {
        // Reduced initial delay for better UX
        await new Promise((resolve) => setTimeout(resolve, 300));

        try {
            // Check for injected initial state from "SSR Lite"
            if (window.__INITIAL_STATE__?.user) {
                appState.setUser(window.__INITIAL_STATE__.user.email);
            } else {
                // Fallback to API call if no initial state was injected
                await getSession();
            }

            // After checking session, check if we should return to a specific menu
            // (e.g. after OAuth redirect)
            const returnMenuId = sessionStorage.getItem("return_menu_id");
            if (returnMenuId) {
                appState.setActiveMenu(parseInt(returnMenuId));
                sessionStorage.removeItem("return_menu_id");
            }
        } catch (error) {
            console.error("Initialization error:", error);
        } finally {
            appState.stopLoading(); // Mark initialization as complete
        }
    });

    // Unified registry of all pages
    const pageRegistry = [
        { id: MENU_ID.ABOUT, label: "About", icon: faInfoCircle, public: true, component: About, showInNav: true, position: 'top' },
        { id: MENU_ID.API_CHECK, label: "API Check", icon: faCheckCircle, public: true, component: Apicheck, showInNav: true, position: 'top' },
        { id: MENU_ID.SECURE, label: "Secure", icon: faShieldAlt, public: false, component: Secure, showInNav: true, position: 'top' },
        { id: MENU_ID.SETTINGS, label: "Settings", icon: faCog, public: true, component: Settings, showInNav: true, position: 'bottom' },
        { id: MENU_ID.LOGIN, label: "Login", icon: faSignInAlt, public: true, component: LogIn, showInNav: true, position: 'bottom', hideIfLoggedIn: true },
        { id: MENU_ID.LOGOUT, label: "Logout", icon: faUser, public: false, component: LogOut, showInNav: true, position: 'bottom' },
    ];

    // Filtered items for Sidebar navigation
    const menuItems = $derived(pageRegistry.filter(item => {
        const isVisible = item.public || appState.isLoggedIn;
        const shouldHide = item.hideIfLoggedIn && appState.isLoggedIn;
        return item.showInNav && isVisible && !shouldHide;
    }));

    // Dynamic current page component based on global state
    const CurrentPage = $derived(pageRegistry.find(p => p.id === appState.activeMenu)?.component);

    // Auto-redirect if logged out and on a protected page
    $effect(() => {
        const activePage = pageRegistry.find(p => p.id === appState.activeMenu);
        if (activePage && !activePage.public && !appState.isLoggedIn) {
            appState.setActiveMenu(MENU_ID.ABOUT); // Default to About
        }
    });
</script>

<div class="app-layout" class:sidebar-pinned={appState.sidebarMode === 'pinned'}>
    <Sidebar navItems={menuItems} />

    <main class="content">
        {#if CurrentPage}
            <CurrentPage />
        {:else}
            <div class="page">
                <h2>Page Not Found or Completed Yet (ID: {appState.activeMenu})</h2>
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
        margin-left: 72px;
        transition: margin-left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .sidebar-pinned .content {
        margin-left: 240px;
    }

    .page {
        padding: 40px;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }

    @media only screen and (max-width: 768px) {
        .app-layout {
            flex-direction: column;
        }

        .content {
            margin-left: 0;
        }

        .sidebar-pinned .content {
            margin-left: 0;
        }
    }
</style>