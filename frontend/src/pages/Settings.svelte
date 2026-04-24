<script lang="ts">
    import { appState } from "../AppState.svelte";
    
    // Dummy state for new settings
    let darkMode = $state(false);
    let notifications = $state(true);
</script>

<div class="page">
    <div class="settings-container">
        <header>
            <h1>Settings</h1>
            <p>Manage your application preferences and account settings.</p>
        </header>

        <div class="settings-grid">
            <section class="settings-section">
                <div class="section-header">
                    <h3>Appearance</h3>
                    <p>Customize how the application looks.</p>
                </div>
                
                <div class="settings-card">
                    <div class="setting-item">
                        <div class="setting-info">
                            <span class="label">Sidebar Behavior</span>
                            <span class="description">Choose how the navigation menu behaves.</span>
                        </div>
                        <div class="options">
                            <button 
                                class:active={appState.sidebarMode === 'hover'} 
                                onclick={() => appState.sidebarMode = 'hover'}
                            >
                                Hover
                            </button>
                            <button 
                                class:active={appState.sidebarMode === 'pinned'} 
                                onclick={() => appState.sidebarMode = 'pinned'}
                            >
                                Pinned
                            </button>
                            <button 
                                class:active={appState.sidebarMode === 'locked'} 
                                onclick={() => appState.sidebarMode = 'locked'}
                            >
                                Locked
                            </button>
                        </div>
                    </div>

                    <div class="setting-item">
                        <div class="setting-info">
                            <span class="label">Dark Mode</span>
                            <span class="description">Switch between light and dark themes.</span>
                        </div>
                        <label class="switch">
                            <input type="checkbox" bind:checked={darkMode}>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
            </section>

            <section class="settings-section">
                <div class="section-header">
                    <h3>Notifications</h3>
                    <p>Control which alerts you receive.</p>
                </div>

                <div class="settings-card">
                    <div class="setting-item">
                        <div class="setting-info">
                            <span class="label">Push Notifications</span>
                            <span class="description">Receive browser notifications for important updates.</span>
                        </div>
                        <label class="switch">
                            <input type="checkbox" bind:checked={notifications}>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
            </section>
        </div>
    </div>
</div>

<style>
    .page {
        padding: 60px 20px;
        display: flex;
        justify-content: center;
        background-color: #f8fafc;
        min-height: 100vh;
    }

    .settings-container {
        width: 100%;
        max-width: 800px;
    }

    header {
        margin-bottom: 40px;
        text-align: left;
    }

    header h1 {
        font-size: 2rem;
        font-weight: 700;
        color: #1e293b;
        margin-bottom: 8px;
    }

    header p {
        color: #64748b;
        font-size: 1.1rem;
    }

    .settings-grid {
        display: flex;
        flex-direction: column;
        gap: 40px;
    }

    .settings-section {
        display: grid;
        grid-template-columns: 250px 1fr;
        gap: 30px;
    }

    @media (max-width: 768px) {
        .settings-section {
            grid-template-columns: 1fr;
            gap: 15px;
        }
    }

    .section-header h3 {
        font-size: 1.25rem;
        font-weight: 600;
        color: #334155;
        margin-bottom: 4px;
    }

    .section-header p {
        font-size: 0.9rem;
        color: #94a3b8;
    }

    .settings-card {
        background: white;
        border-radius: 12px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
        overflow: hidden;
    }

    .setting-item {
        padding: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #f1f5f9;
    }

    .setting-item:last-child {
        border-bottom: none;
    }

    .setting-info {
        display: flex;
        flex-direction: column;
        gap: 4px;
        flex: 1;
        padding-right: 20px;
    }

    .label {
        font-weight: 600;
        color: #1e293b;
    }

    .description {
        font-size: 0.875rem;
        color: #64748b;
    }

    .options {
        display: flex;
        gap: 8px;
        background: #f1f5f9;
        padding: 4px;
        border-radius: 8px;
    }

    button {
        padding: 6px 12px;
        border: none;
        background: transparent;
        border-radius: 6px;
        cursor: pointer;
        transition: all 0.2s;
        font-size: 0.875rem;
        font-weight: 500;
        color: #64748b;
        margin: 0;
    }

    button:hover {
        color: #1e293b;
    }

    button.active {
        background: white;
        color: #10b981;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
    }

    /* Switch styling */
    .switch {
        position: relative;
        display: inline-block;
        width: 44px;
        height: 24px;
        flex-shrink: 0;
    }

    .switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #e2e8f0;
        transition: .4s;
        border-radius: 24px;
    }

    .slider:before {
        position: absolute;
        content: "";
        height: 18px;
        width: 18px;
        left: 3px;
        bottom: 3px;
        background-color: white;
        transition: .4s;
        border-radius: 50%;
    }

    input:checked + .slider {
        background-color: #10b981;
    }

    input:checked + .slider:before {
        transform: translateX(20px);
    }
</style>
