<script lang="ts">
    import { appState } from "../AppState.svelte";
</script>

<div class="page">
    <div class="content-container">
        <!-- Page Header Group -->
        <div class="page-header-block">
            <h1 class="page-main-header">welcome</h1>
            <p class="header-desc">You are successfully logged in as <strong>{appState.user}</strong>.</p>
        </div>

        <!-- Main Content Group -->
        <div class="content-group">
            <div class="group-body">
                <div class="item-block text-center">
                    <div class="icon-container">
                        <svg viewBox="0 0 24 24" width="64" height="64">
                            <path fill="#10b981" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                        </svg>
                    </div>
                    <p class="hint">Use the sidebar or the user menu to explore the application.</p>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    /* Specialized local styles */
    .text-center { text-align: center; }
    .icon-container { margin: 20px 0; }
    .hint { color: #64748b; font-size: 1rem; }
</style>