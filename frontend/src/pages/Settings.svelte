<script lang="ts">
    import { appState } from "../AppState.svelte";
    
    // Dummy state for new settings
    let darkMode = $state(false);
    let notifications = $state(true);
</script>

<div class="page">
    <div class="content-container">
        <!-- Page Header Group -->
        <div class="page-header-block">
            <h1 class="page-main-header">settings</h1>
            <p class="header-desc">Manage your application preferences and account settings.</p>
        </div>

        <!-- Appearance Section Group -->
        <div class="content-group">
            <div class="section-header-block">
                <h2 class="page-sub-header">appearance</h2>
            </div>
            
            <div class="group-body">
                <div class="item-row">
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
        </div>

        <!-- Notifications Section Group -->
        <div class="content-group">
            <div class="section-header-block">
                <h2 class="page-sub-header">notifications</h2>
            </div>

            <div class="group-body">
                <div class="item-row">
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
        </div>
    </div>
</div>

<style>
    /* Local overrides for specialized components like switches and segmented buttons */
    
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

    /*
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
    */

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