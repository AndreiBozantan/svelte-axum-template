<script lang="ts">
    import { Router } from '../Router.svelte';
</script>

<div class="page">
    <div class="content-container">
        <div class="page-header-block">
            <h1 class="page-main-header">svelaxum</h1>
            <p class="header-desc">
                A modern full-stack template built with <strong>Svelte 5</strong> and
                <strong>Axum</strong>.
            </p>
        </div>

        <div class="content-group">
            <div class="group-body">
                <div class="item-block landing-actions">
                    <button class="btn-primary" onclick={() => Router.setActivePage('login')}>
                        Sign In
                    </button>
                    <button class="btn-secondary" onclick={() => Router.setActivePage('register')}>
                        Register
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    /* .btn-primary and .btn-secondary come from the global styles in app.css */
    .landing-actions {
        display: flex;
        gap: 12px;
        justify-content: center;
        padding: 24px 0;
    }
</style>
