<script lang="ts">
    import { appState } from "../AppState.svelte";
    import { onMount } from "svelte";
    import { Fa } from 'svelte-fa';
    import { faSpinner } from '@fortawesome/free-solid-svg-icons';

    let { navItems = [{ label: "logo", id: 0 }], menu = $bindable(1) } = $props();

    // Show mobile icon and display menu
    let showMobileMenu = $state(false);

    // Mobile menu click event handler
    const handleMobileIconClick = (): void => {
        showMobileMenu = !showMobileMenu;
    };

    // Media match query handler
    const mediaQueryHandler = (e: MediaQueryListEvent): void => {
        // Reset mobile state
        if (!e.matches) {
            showMobileMenu = false;
        }
    };

    // Menu selection
    const handleMenuSelection = (id: number): void => {
        menu = id;
        showMobileMenu = false;
    };

    function handleKeyDown(e: KeyboardEvent): void {
        if (e.keyCode === 13) {
            handleMobileIconClick();
        }
    }

    // Attach media query listener on mount hook
    onMount(() => {
        const mediaListener = window.matchMedia("(max-width: 767px)");
        mediaListener.addEventListener("change", mediaQueryHandler);
    });
</script>

<nav>
    <div class="inner">
        <div
            role="button"
            tabindex="0"
            onkeydown={handleKeyDown}
            onclick={handleMobileIconClick}
            class={`mobile-icon${showMobileMenu ? " active" : ""}`}
        >
            <div class="middle-line"></div>
        </div>
        <ul class={`navbar-list${showMobileMenu ? " mobile" : ""}`}>
            {#each navItems as item}
                <li class:active={menu === item.id}>
                    <a
                        href="/"
                        onclick={(e) => {
                            e.preventDefault();
                            handleMenuSelection(item.id);
                        }}>{item.label}</a
                    >
                </li>
            {/each}
        </ul>
        <span class="spinner" class:show={appState.isLoading}>
            <Fa icon={faSpinner} spin={true} />
        </span>
    </div>
</nav>


<style>
    nav {
        background-color: rgba(0, 0, 0, 0.8);
        height: 45px;
    }

    nav li.active {
        background-color: #324232;
    }

    .inner {
        max-width: 980px;
        padding-left: 20px;
        padding-right: 20px;
        margin: auto;
        box-sizing: border-box;
        display: flex;
        align-items: center;
        height: 100%;
    }

    .mobile-icon {
        width: 25px;
        height: 14px;
        position: relative;
        cursor: pointer;
    }

    .mobile-icon:after,
    .mobile-icon:before,
    .middle-line {
        content: "";
        position: absolute;
        width: 100%;
        height: 2px;
        background-color: #fff;
        transition: all 0.4s;
        transform-origin: center;
    }

    .mobile-icon:before,
    .middle-line {
        top: 0;
    }

    .mobile-icon:after,
    .middle-line {
        bottom: 0;
    }

    .mobile-icon:before {
        width: 66%;
    }

    .mobile-icon:after {
        width: 33%;
    }

    .middle-line {
        margin: auto;
    }

    .mobile-icon:hover:before,
    .mobile-icon:hover:after,
    .mobile-icon.active:before,
    .mobile-icon.active:after,
    .mobile-icon.active .middle-line {
        width: 100%;
    }

    .mobile-icon.active:before,
    .mobile-icon.active:after {
        top: 50%;
        transform: rotate(-45deg);
    }

    .mobile-icon.active .middle-line {
        transform: rotate(45deg);
    }

    .navbar-list {
        display: none;
        width: 100%;
        justify-content: space-between;
        margin: 0;
        padding: 0 40px;
    }

    .navbar-list.mobile {
        background-color: rgba(0, 0, 0, 0.8);
        position: fixed;
        display: block;
        height: calc(100% - 45px);
        bottom: 0;
        left: 0;
    }

    .navbar-list li {
        list-style-type: none;
        position: relative;
    }

    .navbar-list li:before {
        content: "";
        position: absolute;
        bottom: 0;
        left: 0;
        width: 100%;
        height: 1px;
        background-color: #424245;
    }

    .navbar-list a {
        color: #fff;
        text-decoration: none;
        display: flex;
        height: 45px;
        align-items: center;
        padding: 0 10px;
        font-size: 13px;
    }

    .spinner {
        position: absolute;
        right: 2em;
        color: orange;
        font-size: 16px;
        opacity: 0;
        transform: scale(0.4);
        transition: opacity 1s ease-out, transform 1s ease-out;
    }

    .spinner.show {
        opacity: 1;
        transform: scale(1);
    }

    @media only screen and (min-width: 767px) {
        .mobile-icon {
            display: none;
        }

        .navbar-list {
            display: flex;
            padding: 0;
        }

        .navbar-list a {
            display: inline-flex;
        }
    }
</style>
