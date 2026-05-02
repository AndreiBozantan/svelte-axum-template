<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { Fa } from 'svelte-fa';
    import { 
        faSignOutAlt, faCog, faIdCard, 
        faHome, faCheckCircle, faInfoCircle, faSignInAlt,
        faUserShield, faUser
    } from '@fortawesome/free-solid-svg-icons';

    // Top navigation items (always visible if permitted)
    const topItems = $derived([
        { id: 'welcome', label: "home", icon: faHome, visible: appState.isLoggedIn },
        { id: 'secure', label: "secure api", icon: faCheckCircle, visible: appState.isLoggedIn },
        { id: 'about', label: "about", icon: faInfoCircle, visible: true },
    ].filter(i => i.visible));

    let showLogoutConfirm = $state(false);
    let isConfirmAnimating = $state(false);
    let logoHoverType = $state(0);
    let popupElement = $state<HTMLElement | null>(null);
    let logoutButton = $state<HTMLElement | null>(null);

    function pickRandomHover() {
        // Pick a random number between 1 and 5, ensuring it's different from the last one if possible
        const next = Math.floor(Math.random() * 5) + 1;
        logoHoverType = next === logoHoverType ? (next % 5) + 1 : next;
    }

    // Bottom navigation items logic
    const handleMenuSelection = (id: string): void => {
        appState.setActivePage(id);
    };

    function confirmLogout() {
        isConfirmAnimating = true;
        // Small delay to show the animation before actual logout
        setTimeout(() => {
            isConfirmAnimating = false;
            showLogoutConfirm = false;
            handleMenuSelection('logout');
        }, 150);
    }

    function handleLogoutSidebarClick() {
        if (showLogoutConfirm) {
            // Just trigger the visual animation to emphasize the confirm button
            isConfirmAnimating = true;
            setTimeout(() => {
                isConfirmAnimating = false;
            }, 150);
        }
    }

    $effect(() => {
        if (showLogoutConfirm && popupElement) {
            const handleGlobalMouseMove = (e: MouseEvent) => {
                const rect = popupElement?.getBoundingClientRect();
                if (!rect) return;
                // Disappear if mouse goes above top border or to the right anywhere on page
                if (e.clientY < rect.top || e.clientX > rect.right) {
                    showLogoutConfirm = false;
                }
            };

            const handleGlobalClick = (e: MouseEvent) => {
                // Don't close if clicking the popup itself or the logout button that triggers it
                if (popupElement && !popupElement.contains(e.target as Node) && 
                    logoutButton && !logoutButton.contains(e.target as Node)) {
                    showLogoutConfirm = false;
                }
            };

            window.addEventListener('mousemove', handleGlobalMouseMove);
            // Delay adding click listener to prevent immediate closing from the click that opened it
            const timer = setTimeout(() => {
                window.addEventListener('click', handleGlobalClick);
            }, 10);
            
            return () => {
                window.removeEventListener('mousemove', handleGlobalMouseMove);
                window.removeEventListener('click', handleGlobalClick);
                clearTimeout(timer);
            };
        }
    });
</script>

<aside class="sidebar">
    <div class="sidebar-header">
        <div 
            class="logo-wrapper" 
            onmouseenter={pickRandomHover}
            onmouseleave={() => logoHoverType = 0}
            role="presentation"
        >
            <div 
                class="logo-icon-box" 
                class:loading={appState.isLoading}
                class:hover-v1={logoHoverType === 1}
                class:hover-v2={logoHoverType === 2}
                class:hover-v3={logoHoverType === 3}
                class:hover-v4={logoHoverType === 4}
                class:hover-v5={logoHoverType === 5}
            >
                <span class="logo-text">S</span>
            </div>
        </div>
    </div>

    <nav class="sidebar-nav">
        <ul>
            {#each topItems as item}
                <li class:active={appState.activePage === item.id}>
                    <button 
                        onclick={() => handleMenuSelection(item.id)}
                        onmouseenter={() => showLogoutConfirm = false}
                    >
                        <span class="nav-icon">
                            <Fa icon={item.icon} />
                        </span>
                        <span class="tooltip">{item.label}</span>
                    </button>
                </li>
            {/each}
        </ul>
    </nav>

    <div class="sidebar-footer">
        <div class="footer-content">
            <!-- Login Button (Visible when logged out) -->
            <button 
                class="footer-btn login" 
                class:active={appState.activePage === 'login'}
                hidden={appState.isLoggedIn}
                onclick={() => handleMenuSelection('login')}
            >
                <span class="footer-icon"><Fa icon={faSignInAlt} /></span>
                <span class="tooltip">Login</span>
            </button>

            <!-- Settings Button (Visible when logged in) -->
            <button 
                class="footer-btn" 
                class:active={appState.activePage === 'settings'}
                hidden={!appState.isLoggedIn}
                onclick={() => handleMenuSelection('settings')}
                onmouseenter={() => showLogoutConfirm = false}
            >
                <span class="footer-icon"><Fa icon={faCog} /></span>
                <span class="tooltip">settings</span>
            </button>
            
            <!-- Logout Wrapper (Visible when logged in) -->
            <div class="logout-wrapper" hidden={!appState.isLoggedIn}>
                <button 
                    bind:this={logoutButton}
                    class="footer-btn logout" 
                    class:active={showLogoutConfirm}
                    onmouseenter={() => showLogoutConfirm = true}
                    onclick={handleLogoutSidebarClick}
                >
                    <span class="footer-icon"><Fa icon={faSignOutAlt} /></span>
                </button>

                <!-- Logout Confirm Popup -->
                <!-- svelte-ignore a11y_mouse_events_have_key_events -->
                <div 
                    bind:this={popupElement} 
                    class="logout-confirm-tooltip-popup"
                    hidden={!showLogoutConfirm}
                >
                    <div class="popup-user-header">
                        <span class="role-icon" class:admin={appState.isAdmin}>
                            <Fa icon={appState.isAdmin ? faUserShield : faUser} />
                        </span>
                        <span class="confirm-user-email">{appState.user}</span>
                    </div>
                    <button 
                        class="confirm-action-btn" 
                        class:animating={isConfirmAnimating}
                        onclick={confirmLogout}
                    >
                        Logout
                    </button>
                </div>
            </div>
        </div>
    </div>
</aside>

<style>
    @import url('https://fonts.googleapis.com/css2?family=Dancing+Script:wght@700&display=swap');

    /* Global utility for the hidden attribute */
    [hidden] { display: none !important; }

    .sidebar {
        width: 72px;
        height: 100vh;
        background-color: #ffffff;
        color: #0f172a;
        display: flex;
        flex-direction: column;
        position: fixed;
        top: 0;
        left: 0;
        box-shadow: 1px 0 12px rgba(0, 0, 0, 0.04);
        border-right: 1px solid #f1f5f9;
        z-index: 1000;
    }

    .sidebar-header {
        padding: 0;
        border-bottom: 1px solid #f1f5f9;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 64px;
        position: relative;
        box-sizing: border-box;
    }

    .logo-wrapper {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        height: 100%;
    }

    .logo-icon-box { 
        width: 42px;
        height: 42px;
        background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
        border-radius: 12px;
        color: #10b981; 
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
        box-shadow: 0 4px 6px -1px rgba(16, 185, 129, 0.1), 0 2px 4px -1px rgba(16, 185, 129, 0.06);
    }

    .logo-text {
        font-family: 'Dancing Script', cursive;
        font-weight: 700;
        font-size: 32px;
        line-height: 1;
        user-select: none;
        transform: rotate(0deg);
        display: inline-block;
        transition: transform 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
    }

    /* Base hover state for background/color */
    .logo-wrapper:hover .logo-icon-box {
        transform: translateY(-2px) scale(1.08);
        background: linear-gradient(135deg, #dcfce7 0%, #bbf7d0 100%);
        color: #059669;
        box-shadow: 0 10px 15px -3px rgba(16, 185, 129, 0.2);
    }

    /* Random Animation Variants (Combinations of tilt and shift) */
    .logo-wrapper:hover .hover-v1 .logo-text { animation: tilt-v1 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
    .logo-wrapper:hover .hover-v2 .logo-text { animation: tilt-v2 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
    .logo-wrapper:hover .hover-v3 .logo-text { animation: tilt-v3 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
    .logo-wrapper:hover .hover-v4 .logo-text { animation: tilt-v4 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }
    .logo-wrapper:hover .hover-v5 .logo-text { animation: tilt-v5 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); }

    @keyframes tilt-v1 {
        0% { transform: rotate(0deg) scale(1); }
        40% { transform: rotate(25deg) scale(1.2); }
        100% { transform: rotate(0deg) scale(1); }
    }

    @keyframes tilt-v2 {
        0% { transform: rotate(0deg) translateY(0); }
        40% { transform: rotate(-25deg) translateY(-8px); }
        100% { transform: rotate(0deg) translateY(0); }
    }

    @keyframes tilt-v3 {
        0% { transform: translateX(0) scale(1); }
        40% { transform: translateX(8px) scale(1.1) rotate(10deg); }
        100% { transform: translateX(0) scale(1); }
    }

    @keyframes tilt-v4 {
        0% { transform: scale(1) rotate(0); }
        40% { transform: scale(0.8) rotate(-15deg); }
        100% { transform: scale(1) rotate(0); }
    }

    @keyframes tilt-v5 {
        0% { transform: translateY(0) rotate(0); }
        40% { transform: translateY(6px) rotate(20deg) scale(1.1); }
        100% { transform: translateY(0) rotate(0); }
    }    @keyframes logo-pulse {
        0% { 
            transform: scale(1); 
        }
        50% { 
            transform: scale(1.25); 
            box-shadow: 0 0 30px 8px rgba(16, 185, 129, 0.35);
        }
        100% { 
            transform: scale(1); 
        }
    }

    .logo-icon-box.loading {
        animation: logo-pulse 1.2s ease-in-out infinite;
    }
    
    .sidebar-nav { 
        flex: 1; 
        padding: 16px 0; 
        display: flex;
        flex-direction: column;
        justify-content: center;
    }

    .sidebar-nav ul { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; }

    .sidebar-nav button, .footer-btn {
        width: 100%;
        height: 48px;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 0 8px;
        color: #64748b;
        background: transparent;
        border: none;
        border-radius: 10px;
        cursor: pointer;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        box-sizing: border-box;
    }

    .nav-icon, .footer-icon { 
        display: flex; 
        justify-content: center; 
        align-items: center; 
        font-size: 20px; 
    }

    .sidebar-nav li button:hover, .footer-btn:hover { 
        background-color: #eefdfd; 
        color: #0f172a; 
    }

    .sidebar-nav li.active button, .footer-btn.active { 
        background-color: #eefdfd; 
        color: #059669; 
    }
    
    .sidebar-nav li.active .nav-icon, .footer-btn.active .footer-icon {
        color: #10b981;
    }

    /* Tooltip */
    .tooltip {
        position: absolute;
        left: 100%;
        top: 50%;
        transform: translateY(-50%) scale(0.95);
        background-color: #eefdfd;
        color: #10b981; 
        font-size: 1rem;
        font-weight: 700;
        font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; 
        letter-spacing: 0.2em;
        padding: 10px 16px;
        border-radius: 8px;
        white-space: nowrap;
        pointer-events: none;
        opacity: 0;
        z-index: 2000;
        transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
        box-shadow: 4px 0 12px rgba(0, 0, 0, 0.08);
        border: 1px solid #f1f5f9;
        border-left: none;
    }

    .logout-confirm-tooltip-popup {
        position: absolute;
        left: 100%;
        bottom: -16px;
        background-color: #fcfcff;
        border: 1px solid #f1f5f9;
        border-left: none;
        box-shadow: 4px 0 12px rgba(0, 0, 0, 0.08);
        border-radius: 0 12px 12px 0;
        padding: 14px 20px;
        z-index: 3000;
        white-space: nowrap;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 12px;
        animation: slideIn 0.15s ease-out;
        min-width: 140px;
    }

    @keyframes slideIn {
        from { opacity: 0; transform: translateX(-5px); }
        to { opacity: 1; transform: translateX(0); }
    }

    .popup-user-header {
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 6px;
        width: 100%;
    }

    .role-icon {
        font-size: 18px;
        color: #64748b;
        display: flex;
        align-items: center;
        justify-content: center;
        background: #f1f5f9;
        width: 36px;
        height: 36px;
        border-radius: 50%;
    }

    .role-icon.admin {
        color: #10b981;
        background: #ecfdf5;
    }

    .confirm-user-email { 
        margin: 0; 
        font-size: 13px; 
        font-weight: 400;
        color: #475569;
        display: block;
    }

    .confirm-action-btn {
        background: #e11d48;
        color: white;
        border: none;
        border-radius: 8px;
        padding: 8px 16px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease-in-out;
        width: 100%;
    }

    .confirm-action-btn:hover { background: #be123c; }
    .confirm-action-btn.animating { transform: scale(1.05); background: #be123c; }

    button:hover .tooltip { 
        opacity: 1; 
        transform: translateY(-50%) scale(1); 
    }

    .sidebar-footer { 
        padding: 16px 0;
        border-top: 1px solid #f1f5f9; 
    }

    .footer-content { display: flex; flex-direction: column; width: 100%; gap: 4px; }

    .logout-wrapper { position: relative; width: 100%; padding: 0 8px; box-sizing: border-box; }
    .logout:hover, .logout.active { color: #e11d48; background-color: #fff1f2; }
    .logout:hover .footer-icon, .logout.active .footer-icon { color: #e11d48; }
    .logout:hover  { color: #e11d48; }

    @media only screen and (max-width: 768px) {
        .sidebar { width: 100%; height: auto; position: fixed; bottom: 0; top: auto; border-right: none; border-top: 1px solid #f1f5f9; flex-direction: row; }
        .sidebar-header { display: none; }
        .sidebar-nav { padding: 8px; }
        .sidebar-nav ul { flex-direction: row; justify-content: space-around; width: 100%; }
        .sidebar-footer { border-top: none; padding: 8px; flex: 1; display: flex; justify-content: flex-end; }
        .tooltip { display: none; }
    }
</style>
