<script lang="ts">
</script>

<div class="page">
    <div class="content-container">
        <div class="content-grid">

            <section class="info-section">
                <div class="info-card">
                    <div class="info-item">
                        <div class="info-header">About</div>
                    </div>
                    <div class="info-item-block">
                        <p>Svelaxum is a modern full-stack template built with <strong>Svelte 5</strong> and <strong>Axum</strong>. This project is designed to provide a solid foundation for building fast, scalable, and type-safe web applications.</p>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Version</div>
                        <div class="info-value">v1.0.0-beta</div>
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

    .content-container {
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

    .content-grid {
        display: flex;
        flex-direction: column;
        gap: 40px;
    }

    .info-section {
        display: grid;
        grid-template-columns: 1fr;
        gap: 30px;
    }

    @media (max-width: 768px) {
        .info-section {
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

    .info-card {
        background: white;
        border-radius: 12px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px rgba(0, 0, 0, 0.06);
        overflow: hidden;
    }

    .info-item {
        padding: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 1px solid #f1f5f9;
    }

    .info-item-block {
        padding: 24px;
        border-bottom: 1px solid #f1f5f9;
    }

    .info-item-block h4 {
        margin-bottom: 12px;
        color: #1e293b;
    }

    .info-item-block p {
        color: #64748b;
        line-height: 1.6;
        font-size: 0.95rem;
    }

    .info-item:last-child, .info-item-block:last-child {
        border-bottom: none;
    }

    .info-header {
        font-size: 1.25rem;
        font-weight: 600;
        color: #334155;
    }

    .info-label {
        color: #1e293b;
    }

    .info-value {
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .user-name {
        color: #64748b;
        font-size: 0.9rem;
    }

    .status-badge {
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.025em;
    }

    .success {
        background-color: #dcfce7;
        color: #166534;
    }

    .warning {
        background-color: #fef9c3;
        color: #854d0e;
    }
</style>
