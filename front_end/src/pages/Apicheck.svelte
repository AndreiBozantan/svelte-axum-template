<script lang="ts">
    import { getApi } from "../ts/fetch";

    let token = $state("123456789");
    let response = $state("");

    async function handlebutton(): Promise<void> {
        response = "<nothing returned>";
        response = JSON.stringify(await getApi(token));
        console.log(`TOKEN: ${token}`);
        console.log(`RESPONSE: ${response}`);
    }
</script>

<div>
    <container class="wider mobile">
        <p>
            You can try using the default API to access api of backend server or
            you can try entering a bad token to see what happens. This can be
            used with or without logging in.
        </p>

        <label for="apiToken">API Token</label>
        <input class="input" type="text" bind:value={token} />
        <button onclick={handlebutton}> Get /api </button>

        <p class="mono">RESPONSE: {response}</p>
    </container>
</div>

<style>
    div {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin: 25px;
    }

    @media only screen and (max-width: 620px) {
        container.mobile {
            width: 300px;
        }
    }
</style>
