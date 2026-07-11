<script lang="ts">
    import { Router } from '../Router.svelte';
</script>

<div class="page">
    <div class="content-container">
        <div class="page-header-block">
            <h1 class="page-main-header">page not found</h1>
            <p class="header-desc">
                There is no page at <strong>/{Router.activePage}</strong>.
            </p>
        </div>

        <div class="content-group">
            <div class="group-body">
                <div class="item-block not-found-actions">
                    <button class="btn-primary" onclick={() => Router.setActivePage('')}>
                        Go Home
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    /* .btn-primary comes from the global styles in app.css */
    .not-found-actions {
        display: flex;
        justify-content: center;
        padding: 24px 0;
    }
</style>
