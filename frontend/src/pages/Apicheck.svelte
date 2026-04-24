<script lang="ts">
    import { getApi, getHealth } from "../lib/fetch";

    let response = $state("");

    async function handleApiCheck(): Promise<void> {
        response = "Loading...";
        try {
            const data = await getApi();
            response = JSON.stringify(data, null, 2);
        } catch (e) {
            response = `Error: ${e}`;
        }
    }

    async function handleHealthCheck(): Promise<void> {
        response = "Loading...";
        try {
            const data = await getHealth();
            response = JSON.stringify(data, null, 2);
        } catch (e) {
            response = `Error: ${e}`;
        }
    }
</script>

<div class="page">
    <div class="content-container">
        <div class="content-grid">
            <section class="info-section">
                <div class="info-card">
                    <div class="info-item">
                        <div class="info-header">API Check</div>
                    </div>
                    <div class="info-item-block">
                        <p>
                            Test the connection to the backend server. The <strong>/api</strong> check requires 
                            you to be logged in, while the <strong>/health</strong> check is public and 
                            verifies the database connection.
                        </p>
                    </div>
                    
                    <div class="info-item-block">
                        <div class="button-group">
                            <button class="btn" onclick={handleApiCheck}>Get /api</button>
                            <button class="btn btn-secondary" onclick={handleHealthCheck}>Get /health</button>
                        </div>
                    </div>

                    <div class="info-item-block">
                        <div class="info-label">Response</div>
                        <pre class="response-box">{response}</pre>
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

    .info-item:last-child, .info-item-block:last-child {
        border-bottom: none;
    }

    .info-header {
        font-size: 1.25rem;
        font-weight: 600;
        color: #334155;
    }

    .info-label {
        display: block;
        margin-bottom: 8px;
        color: #1e293b;
        font-weight: 500;
    }

    .input {
        width: 100%;
        padding: 10px 12px;
        border-radius: 6px;
        border: 1px solid #e2e8f0;
        font-size: 0.95rem;
        margin-bottom: 16px;
        box-sizing: border-box;
    }

    .button-group {
        display: flex;
        gap: 12px;
    }

    .btn {
        padding: 10px 20px;
        border-radius: 6px;
        font-weight: 600;
        cursor: pointer;
        border: none;
        background-color: #3b82f6;
        color: white;
        transition: background-color 0.2s;
    }

    .btn:hover {
        background-color: #2563eb;
    }

    .btn-secondary {
        background-color: #64748b;
    }

    .btn-secondary:hover {
        background-color: #475569;
    }

    .response-box {
        margin-top: 12px;
        padding: 16px;
        background-color: #f1f5f9;
        border-radius: 8px;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 0.85rem;
        color: #334155;
        overflow-x: auto;
        white-space: pre-wrap;
        word-break: break-all;
    }

    p {
        color: #64748b;
        line-height: 1.6;
        font-size: 0.95rem;
    }
</style>
