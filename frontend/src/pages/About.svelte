<script lang="ts">
    import { onMount } from "svelte";

    let healthStatus = $state("Checking...");
    let healthColor = $state("#64748b");

    onMount(async () => {
        try {
            const res = await fetch("/api/health");
            if (res.ok) {
                healthStatus = "Operational";
                healthColor = "#10b981";
            } else {
                healthStatus = "Service issues";
                healthColor = "#f59e0b";
            }
        } catch (e) {
            healthStatus = "Offline";
            healthColor = "#ef4444";
        }
    });
</script>

<div class="page">
    <div class="content-container">
        <!-- Page Header Group -->
        <div class="page-header-block">
            <h1 class="page-main-header">about</h1>
            <p class="header-desc">
                Svelaxum is a modern full-stack template built with <strong>Svelte 5</strong> and <strong>Axum</strong>.
            </p>
        </div>
        
        <!-- Details Section Group -->
        <div class="content-group">
            <div class="section-header-block">
                <h2 class="page-sub-header">platform details</h2>
            </div>

            <div class="group-body">
                <div class="item-row description-row">
                    <p>
                        This project provides a solid foundation for building fast, scalable, and type-safe web applications 
                        with a focus on developer experience and performance.
                    </p>
                </div>

                <div class="item-row">
                    <div class="info-label">Version</div>
                    <div class="info-value">v1.0.0-beta</div>
                </div>
                
                <div class="item-row">
                    <div class="info-label">System Status</div>
                    <div class="info-value" style="color: {healthColor}; font-weight: 600;">
                        {healthStatus}
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    /* Local specialized styles */
    .description-row p {
        color: #475569;
        line-height: 1.6;
        margin: 0;
        font-size: 1.05rem;
    }
</style>