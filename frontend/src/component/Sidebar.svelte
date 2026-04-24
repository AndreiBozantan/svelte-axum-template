<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { Fa } from 'svelte-fa';
    import { faSpinner, faUser, faSignOutAlt, faS, faExclamationTriangle } from '@fortawesome/free-solid-svg-icons';
    import { MENU_ID } from '../lib/constants';
    import { onMount } from "svelte";

    let { navItems = [] } = $props();
    
    let isHovered = $state(false);
    let showLogoutConfirm = $state(false);
    let popupRef: HTMLDivElement | undefined = $state();
    let logoutButtonRef: HTMLButtonElement | undefined = $state();
    
    const topItems = $derived(navItems.filter(i => i.position !== 'bottom'));
    const bottomItems = $derived(navItems.filter(i => i.position === 'bottom'));

    // isExpanded logic:
    let isExpanded = $derived(appState.sidebarMode === 'pinned' || (appState.sidebarMode === 'hover' && isHovered));

    // Menu selection
    const handleMenuSelection = (id: number): void => {
        if (id === MENU_ID.LOGOUT) {
            showLogoutConfirm = !showLogoutConfirm;
        } else {
            appState.setActiveMenu(id);
            showLogoutConfirm = false;
        }
    };

    const confirmLogout = () => {
        appState.setActiveMenu(MENU_ID.LOGOUT);
        showLogoutConfirm = false;
    };

    const cancelLogout = () => {
        showLogoutConfirm = false;
    };

    const handleItemHover = (id: number) => {
        if (id !== MENU_ID.LOGOUT && showLogoutConfirm) {
            showLogoutConfirm = false;
        }
    };

    // Close popup on click outside
    onMount(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (showLogoutConfirm && 
                popupRef && !popupRef.contains(event.target as Node) && 
                logoutButtonRef && !logoutButtonRef.contains(event.target as Node)) {
                showLogoutConfirm = false;
            }
        };

        window.addEventListener('click', handleClickOutside, true);
        return () => window.removeEventListener('click', handleClickOutside, true);
    });

    const useSidebarModes = false;
    const handleCycleMode = () => {
        appState.cycleSidebarMode();
    };

    // Button state helpers
    const isPinnedMode = $derived(appState.sidebarMode === 'pinned');
    const isLockedMode = $derived(appState.sidebarMode === 'locked');

    const getModeTooltip = $derived(() => {
        if (isPinnedMode) return "Pinned (Click to Lock Collapsed)";
        if (isLockedMode) return "Locked Collapsed (Click to Enable Hover)";
        return "Hover Expandable (Click to Pin)";
    });
</script>

<!-- svelte-ignore a11y_mouse_events_have_key_events -->
<aside 
    class="sidebar" 
    class:pinned={isPinnedMode} 
    class:locked={isLockedMode}
    class:expanded={isExpanded}
    onmouseenter={() => isHovered = true}
    onmouseleave={() => {
        isHovered = false;
    }}
>
    <div class="sidebar-header">
        <div class="logo-wrapper">
            <div class="logo-icon-box" class:hidden={isExpanded}>
                {#if appState.isLoading}
                    <div class="logo-spinner">
                        <Fa icon={faSpinner} spin={true} />
                    </div>
                {/if}
                <Fa icon={faS} />
            </div>
            <h2 class="logo" class:hidden={!isExpanded}>Svelaxum</h2>
            <span class="tooltip">Svelaxum</span>
        </div>
    </div>

    <nav class="sidebar-nav">
        <ul>
            {#each topItems as item}
                <li class:active={appState.activeMenu === item.id}>
                    <a
                        href="/"
                        onclick={(e) => {
                            e.preventDefault();
                            handleMenuSelection(item.id);
                        }}
                        onmouseenter={() => handleItemHover(item.id)}
                    >
                        <span class="nav-icon">
                            <Fa icon={item.icon} />
                        </span>
                        <span class="nav-label" class:hidden={!isExpanded}>{item.label}</span>
                        <span class="tooltip">{item.label}</span>
                    </a>
                </li>
            {/each}
        </ul>
    </nav>

    <div class="sidebar-footer">
        <div class="footer-content">
            {#each bottomItems as item}
                <div class="user-status-container">
                    {#if item.id === MENU_ID.LOGOUT && showLogoutConfirm}
                        <div bind:this={popupRef} class="logout-confirm-popup" class:expanded={isExpanded}>
                            <div class="confirm-content">
                                <span class="confirm-icon"><Fa icon={faExclamationTriangle} /></span>
                                <span class="confirm-text">Sign out?</span>
                            </div>
                            <div class="confirm-user">{appState.user}</div>
                            <div class="confirm-actions">
                                <button class="btn-confirm" onclick={confirmLogout}>Logout</button>
                                <button class="btn-cancel" onclick={cancelLogout}>Cancel</button>
                            </div>
                        </div>
                    {/if}

                    {#if item.id === MENU_ID.LOGOUT}
                        <button 
                            bind:this={logoutButtonRef}
                            class="user-status-btn"
                            class:active={appState.activeMenu === item.id}
                            class:logout={true}
                            class:confirming={showLogoutConfirm}
                            onclick={() => handleMenuSelection(item.id)}
                            onmouseenter={() => handleItemHover(item.id)}
                        >
                            <span class="icon-container footer-icon">
                                <Fa icon={faUser} class="user-icon" />
                                <Fa icon={faSignOutAlt} class="logout-icon" />
                            </span>
                            <span class="username-text" class:hidden={!isExpanded}>{appState.user}</span>
                            <span class="logout-text" class:hidden={!isExpanded}>Log-out</span>
                            {#if !showLogoutConfirm}
                                <span class="tooltip">Log-out <br /> {appState.user}</span>
                            {/if}
                        </button>
                    {:else}
                        <button 
                            class="user-status-btn"
                            class:active={appState.activeMenu === item.id}
                            onclick={() => handleMenuSelection(item.id)}
                            onmouseenter={() => handleItemHover(item.id)}
                        >
                            <span class="footer-icon">
                                <Fa icon={item.icon} />
                            </span>
                            <span class="footer-text" class:hidden={!isExpanded}>{item.label}</span>
                            <span class="tooltip">{item.label}</span>
                        </button>
                    {/if}
                </div>
            {/each}

            {#if useSidebarModes}
                <div class="mode-control-container">
                    <button 
                        class="mode-toggle-btn" 
                        class:pinned={isPinnedMode}
                        onclick={handleCycleMode} 
                        aria-label="Toggle Sidebar Mode"
                        onmouseenter={() => showLogoutConfirm = false}
                    >
                        <div class="mode-symbol-container">
                            <div class="mode-symbol" class:wide={isPinnedMode}></div>
                        </div>
                        <span class="tooltip">{getModeTooltip()}</span>
                    </button>
                </div>
            {/if}
        </div>
    </div>
</aside>

<style>
    .sidebar {
        width: 72px;
        height: 100vh;
        background-color: #f8fafc; /* Subtle light gray-blue */
        color: #1e293b;
        display: flex;
        flex-direction: column;
        position: fixed;
        top: 0;
        left: 0;
        box-shadow: 0px 0 8px rgba(0, 0, 0, 0.05);
        z-index: 1000;
        --border-right: 1px solid #e2e8f0;
        transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1), box-shadow 0.3s;
        overflow: visible;
    }

    .sidebar.expanded {
        width: 240px;
        box-shadow: 10px 0 15px rgba(0, 0, 0, 0.05);
    }

    .sidebar.pinned {
        box-shadow: 0px 0 8px rgba(0, 0, 0, 0.05);
    }

    .sidebar-header {
        padding: 24px 16px;
        border-bottom: 1px solid #e2e8f0;
        display: flex;
        align-items: center;
        min-height: 80px;
        box-sizing: border-box;
    }

    .logo-wrapper {
        display: flex;
        align-items: center;
        width: 100%;
        justify-content: center;
        position: relative;
        height: 1em;
    }

    .sidebar.expanded .logo-wrapper {
        justify-content: flex-start;
    }

    .logo-icon-box {
        font-size: 1.7em;
        color: #10b981;
        display: grid;
        place-items: center;
    }

    .logo-icon-box > :global(*) {
        grid-area: 1 / 1;
    }

    .logo-spinner {
        font-size: 2.2em;
        opacity: 0.4;
    }

    .logo {
        margin: 0;
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.5px;
        color: #059669;
        white-space: nowrap;
        opacity: 1;
        transition: opacity 0.2s;
    }

    .hidden {
        display: none !important;
        opacity: 0;
    }

    /* Modern Bar Toggle Button */
    .mode-toggle-btn {
        background: transparent;
        border: none;
        color: #94a3b8; /* Subtle gray */
        width: 100%;
        height: 44px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: all 0.2s;
        position: relative;
        border-radius: 8px;
        padding: 12px 16px;
    }

    .sidebar:not(.expanded) .mode-toggle-btn {
        padding: 12px;
        justify-content: center;
    }

    .sidebar.expanded .mode-toggle-btn {
        justify-content: flex-start;
    }

    .mode-toggle-btn:hover {
        background-color: rgba(148, 163, 184, 0.1);
        color: #64748b;
    }

    .mode-toggle-btn.pinned {
        color: #475569;
    }

    .confirm-actions {
        display: flex;
        gap: 8px;
    }

    .mode-symbol-container {
        min-width: 20px;
        display: flex;
        justify-content: center;
        align-items: center;
    }

    .mode-symbol {
        width: 3px;
        height: 18px; /* Standardized to 18px */
        background-color: currentColor;
        border-radius: 2px;
        transition: width 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .mode-symbol.wide {
        width: 12px; /* Wider in pinned mode */
    }

    .sidebar-nav {
        flex: 1;
        padding: 12px;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }

    .sidebar:not(.expanded) .sidebar-nav {
        padding: 12px 8px;
    }

    .sidebar-nav ul {
        list-style: none;
        padding: 0;
        margin: 0;
        display: flex;
        flex-direction: column; gap: 4px;
    }

    .sidebar-nav li {
        margin-bottom: 4px;
        position: relative;
    }

    .sidebar-nav a {
        display: flex;
        align-items: center;
        padding: 12px 16px;
        color: #64748b;
        text-decoration: none;
        border-radius: 8px;
        font-size: 15px;
        font-weight: 500;
        transition: all 0.2s ease;
        white-space: nowrap;
        position: relative;
    }

    .sidebar:not(.expanded) .sidebar-nav a {
        padding: 12px;
        justify-content: center;
    }

    .nav-icon, .footer-icon {
        min-width: 20px;
        display: flex;
        justify-content: center;
        align-items: center;
        font-size: 18px;
    }

    .nav-label {
        margin-left: 12px;
        transition: opacity 0.2s;
    }

    .sidebar-nav li:hover a {
        background-color: rgba(148, 163, 184, 0.1);
        color: #0f172a;
    }

    .sidebar-nav li.active a {
        background-color: #10b981;
        color: white;
    }

    /* Tooltip styles */
    .tooltip {
        position: absolute;
        left: calc(100% + 8px);
        top: 50%;
        transform: translateY(-50%) translateX(-5px);
        background-color: #aea9ab;
        /* background-color: #1e293b; */
        color: white;
        padding: 10px 20px;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        white-space: nowrap;
        pointer-events: none;
        opacity: 0;
        z-index: 2000;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        transition: opacity 0.1s ease, transform 0.1s ease;
        display: block;
    }

    .logo-wrapper .tooltip {
        background-color: #f8fafc;
        color: #059669;
        font-size: 20px;
        font-weight: 700;
        letter-spacing: -0.5px;
        border: 1px solid #e2e8f0;
        padding: 8px 16px;
    }

    .sidebar.expanded .tooltip {
        display: none !important;
    }

    li:hover .tooltip, 
    .user-status-btn:hover .tooltip,
    .mode-toggle-btn:hover .tooltip,
    .logo-wrapper:hover .tooltip {
        opacity: 1 !important;
        transform: translateY(-50%) translateX(0) !important;
    }

    .sidebar-footer {
        padding: 12px;
        border-top: 1px solid #e2e8f0;
        min-height: 64px;
    }

    .footer-content {
        display: flex;
        flex-direction: column;
        gap: 4px;
        align-items: center;
    }

    .sidebar.expanded .footer-content {
        align-items: flex-start;
    }

    .user-status-container {
        width: 100%;
        position: relative;
    }

    .mode-control-container {
        width: 100%;
        display: flex;
        justify-content: center;
        padding-top: 8px;
    }

    .sidebar.expanded .mode-control-container {
        justify-content: flex-start;
        padding-left: 0;
    }

    .user-status-btn {
        width: 100%;
        display: flex;
        align-items: center;
        padding: 12px 16px;
        border: none;
        border-radius: 8px;
        background: transparent;
        color: #64748b;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
        text-align: left;
        white-space: nowrap;
        position: relative;
    }

    .sidebar:not(.expanded) .user-status-btn {
        padding: 12px;
        justify-content: center;
    }

    .user-status-btn:hover {
        background-color: rgba(148, 163, 184, 0.1);
        color: #0f172a;
    }

    .user-status-btn.active {
        background-color: #10b981;
        color: white;
    }

    .user-status-btn.confirming {
        background-color: #fef2f2;
        color: #ef4444;
    }

    .icon-container {
        position: relative;
        width: 20px;
        height: 18px;
        display: flex;
        align-items: center;
        justify-content: center;
        min-width: 20px;
    }

    :global(.logout-icon) {
        position: absolute;
        opacity: 0;
        transform: translateX(-5px);
        transition: all 0.2s ease;
    }

    .user-status-btn.logout:hover :global(.user-icon) {
        opacity: 0;
        transform: translateX(5px);
    }

    .user-status-btn.logout:hover :global(.logout-icon) {
        opacity: 1;
        transform: translateX(0);
        color: #ef4444;
    }

    .logout-text {
        position: absolute;
        left: 48px;
        opacity: 0;
        transform: translateY(10px);
        transition: all 0.2s ease;
        color: #ef4444;
    }

    .username-text {
        margin-left: 12px;
        transition: all 0.2s ease;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 130px;
    }

    .user-status-btn.logout:hover .username-text {
        opacity: 0;
        transform: translateY(-10px);
    }

    .user-status-btn.logout:hover .logout-text {
        opacity: 1;
        transform: translateY(0);
    }

    /* Logout confirmation popup */
    .logout-confirm-popup {
        position: absolute;
        bottom: calc(100% + 8px);
        left: 8px;
        right: 8px;
        background: white;
        border: 1px solid #fee2e2;
        border-radius: 12px;
        padding: 14px;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
        z-index: 3000; /* Higher than tooltip (2000) */
        display: flex;
        flex-direction: column;
        gap: 12px;
        animation: slideUp 0.2s ease-out;
        min-width: 160px;
        max-width: 220px;
    }

    .sidebar:not(.expanded) .logout-confirm-popup {
        left: 72px;
        bottom: 12px;
        width: auto;
    }

    @keyframes slideUp {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }

    .confirm-content {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .confirm-icon {
        color: #ef4444;
        font-size: 14px;
        flex-shrink: 0;
    }

    .confirm-text {
        font-size: 14px;
        font-weight: 700;
        color: #1e293b;
        white-space: nowrap;
    }

    .confirm-user {
        font-size: 12px;
        color: #64748b;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-top: -8px;
        padding-left: 22px;
    }

    .btn-confirm {
        flex: 1;
        background: #ef4444;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 8px;
        font-size: 12px;
        font-weight: 700;
        cursor: pointer;
        transition: background 0.2s;
    }

    .btn-confirm:hover {
        background: #dc2626;
    }

    .btn-cancel {
        flex: 1;
        background: #f1f5f9;
        color: #475569;
        border: none;
        border-radius: 6px;
        padding: 8px;
        font-size: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
    }

    .btn-cancel:hover {
        background: #e2e8f0;
    }

    .footer-text {
        margin-left: 12px;
    }

    .spinner-container {
        display: flex;
        align-items: center;
        color: #10b981;
        font-size: 14px;
        padding: 12px 8px;
        white-space: nowrap;
        justify-content: center;
        width: 100%;
    }

    .sidebar.expanded .spinner-container {
        justify-content: flex-start;
        padding-left: 16px;
    }

    @media only screen and (max-width: 768px) {
        .sidebar, .sidebar.expanded {
            width: 100%;
            height: auto;
            position: relative;
            border-right: none;
            border-bottom: 1px solid #e2e8f0;
            box-shadow: none;
            overflow: hidden;
        }

        .tooltip {
            display: none !important;
        }

        .sidebar-header {
            padding: 15px 24px;
            min-height: auto;
        }

        .logo-wrapper {
            justify-content: flex-start;
        }

        .logo-icon-box {
            display: none;
        }

        .sidebar-nav {
            padding: 10px;
        }

        .sidebar-nav ul {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }

        .sidebar-nav li {
            margin-bottom: 0;
        }

        .sidebar-nav a {
            padding: 8px 12px;
            font-size: 14px;
        }

        .nav-label {
            display: block !important;
            opacity: 1 !important;
        }

        .logo {
            display: block !important;
            opacity: 1 !important;
        }

        .sidebar-footer {
            border-top: none;
            border-left: 1px solid #e2e8f0;
            padding: 10px;
            min-height: auto;
        }
        
        .footer-content {
            flex-direction: row;
        }

        .mode-control-container {
            display: none;
        }

        .user-status-btn {
            padding: 8px 12px;
        }

        .footer-text, .username-text {
            display: block !important;
        }

        .logout-confirm-popup {
            position: fixed;
            bottom: auto;
            top: 80px;
            left: 50%;
            transform: translateX(-50%);
            width: 280px;
            max-width: 90vw;
        }
    }
</style>