<script lang="ts">
    import { appState } from "./AppState.svelte";
    import { getSession } from "./ts/auth";
    import NavBar from "./component/Navbar.svelte";
    import LogIn from "./pages/Login.svelte";
    import LogOut from "./pages/Logout.svelte";
    import Secure from "./pages/Secure.svelte";
    import Apicheck from "./pages/Apicheck.svelte";
    import { onMount } from "svelte";

    let menu = $state(1);

    // check if logged in
    onMount(async () => {
        try {
            // Simulate a delay for initialization
            await new Promise((resolve) => setTimeout(resolve, 300));
            await getSession();
        }
        finally {
            appState.stopLoading(); // Mark initialization as complete
        }
    });

    const menuItems = $derived(appState.isLoggedIn ?
        [
            { label: "About", id: 1 },
            { label: "Secure", id: 3 },
            { label: "API Check", id: 5 },
            { label: "Logout", id: 4 },
        ]
        :
        [
            { label: "About", id: 1 },
            { label: "API Check", id: 5 },
            { label: "Login", id: 2 },
        ]);
</script>

<!-- MENU BAR ON TOP -->
<NavBar navItems={menuItems} bind:menu />

<!-- PAGE LOADING -->
{#if menu === 1}
    <div>
        <container>
            {#if appState.isLoggedIn}
                <h4>Logged In as {appState.user}</h4>
            {:else}
                <h4>Requires Login</h4>
            {/if}
            <p>ABOUT</p>
        </container>
    </div>
{:else if menu === 2}
    <LogIn />
{:else if menu === 3}
    <Secure />
{:else if menu === 4}
    <LogOut />
{:else if menu === 5}
    <Apicheck />
{:else}
    <h2>Page Not Found or Completed Yet</h2>
{/if}

<style>
    div {
        margin: 25px;
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }
</style>
