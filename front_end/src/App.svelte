<script lang="ts">
    import { user } from "./ts/store";
    import { getSession } from "./ts/auth";
    import NavBar from "./component/Navbar.svelte";
    import LogIn from "./pages/Login.svelte";
    import LogOut from "./pages/Logout.svelte";
    import Secure from "./pages/Secure.svelte";
    import Apicheck from "./pages/Apicheck.svelte";
    import { onMount } from "svelte";

    let menu = $state(1);
    let isInitializing = $state(true); // Flag to track initial loading state

    // Use $derived for reactive derivations (replacing $:)
    const loggedin = $derived($user !== "" && $user !== undefined);

    // check if logged in
    onMount(async () => {
        await getSession();
        isInitializing = false; // Mark initialization as complete
    });

    const getMenuItems = (loggedin: boolean) => {
        if (loggedin) {
            return [
                { label: "About", id: 1 },
                { label: "Secure", id: 3 },
                { label: "API Check", id: 5 },
                { label: "Logout", id: 4 },
            ];
        } else {
            return [
                { label: "About", id: 1 },
                { label: "API Check", id: 5 },
                { label: "Login", id: 2 },
            ];
        }
    };
</script>

<!-- MENNU BAR ON TOP -->
{#if !isInitializing}
  <NavBar navItems={getMenuItems(loggedin)} bind:menu />
{:else}
  <nav>
    <div class="inner">
      <ul class="navbar-list">
        <li><a href="/">Loading...</a></li>
      </ul>
    </div>
  </nav>
{/if}

<!-- PAGE LOADING -->
{#if isInitializing}
    <h2>Loading...</h2>
{:else}
    {#if menu === 1}
        <div>
            <container>
                {#if !loggedin}
                    <h4>Requires Login</h4>
                {:else}
                    <h4>Logged In as {$user}</h4>
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
