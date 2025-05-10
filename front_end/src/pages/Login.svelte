<script lang="ts">
    import { user } from "./../ts/store";
    import { getSession, postLogin } from "./../ts/auth";

    let username = $state("");
    let password = $state("");
    let errorMessage = $state("");

    async function handleLogin(): Promise<void> {
        let loginResponse = await postLogin(username, password);
        if (loginResponse.result == "error") {
            errorMessage = loginResponse.message;
        } else {
            getSession();
        }
    }
</script>

{#if !$user}
    {#if errorMessage}
        <div>
            {errorMessage}
        </div>
    {/if}
    <div>
        <container>
            <div>
                <label for="username">Username</label>
                <input
                    class="input"
                    type="username"
                    placeholder="username"
                    bind:value={username}
                />
                <label for="password">Password</label>
                <input
                    class="input"
                    type="password"
                    placeholder="password"
                    bind:value={password}
                />
                <button onclick={handleLogin}> Login </button>
            </div>
        </container>
    </div>
{:else}
    <div>
        <container>
            Logged in as: {$user} <br />
            Now you may access the <strong>secure area </strong>from the Nav above
        </container>
    </div>
{/if}

<style>
    div {
        margin: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
    }

    label {
        width: 210px;
        text-align: left;
    }
</style>
