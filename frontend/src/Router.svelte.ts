import About from './pages/About.svelte';
import Dashboard from './pages/Dashboard.svelte';
import Home from './pages/Home.svelte';
import LogIn from './pages/Login.svelte';
import LogOut from './pages/Logout.svelte';
import Register from './pages/Register.svelte';
import SecureApi from './pages/SecureApi.svelte';
import Settings from './pages/Settings.svelte';
import type { Component } from 'svelte';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';
import {
    faSignOutAlt,
    faCog,
    faSignInAlt,
    faHome,
    faGauge,
    faUserPlus,
    faCheckCircle,
    faInfoCircle,
} from '@fortawesome/free-solid-svg-icons';

export type PageDefinition = {
    id: string;
    label: string;
    component: Component;
    public: boolean;
    icon: IconDefinition;
    navPosition?: 'top' | 'footer' | 'none';
    // only reachable/visible while logged out (home, login, register)
    anonymousOnly?: boolean;
    // only visible while logged in (logout)
    authenticatedOnly?: boolean;
};

export const Pages: PageDefinition[] = [
    {
        id: '',
        label: 'home',
        component: Home,
        public: true,
        icon: faHome,
        navPosition: 'top',
        anonymousOnly: true,
    },
    {
        id: 'dashboard',
        label: 'dashboard',
        component: Dashboard,
        public: false,
        icon: faGauge,
        navPosition: 'top',
    },
    {
        id: 'secure',
        label: 'secure api',
        component: SecureApi,
        public: false,
        icon: faCheckCircle,
        navPosition: 'top',
    },
    {
        id: 'about',
        label: 'about',
        component: About,
        public: true,
        icon: faInfoCircle,
        navPosition: 'top',
    },
    {
        id: 'settings',
        label: 'settings',
        component: Settings,
        public: false,
        icon: faCog,
        navPosition: 'footer',
    },
    {
        id: 'login',
        label: 'login',
        component: LogIn,
        public: true,
        icon: faSignInAlt,
        navPosition: 'footer',
        anonymousOnly: true,
    },
    {
        id: 'register',
        label: 'register',
        component: Register,
        public: true,
        icon: faUserPlus,
        navPosition: 'footer',
        anonymousOnly: true,
    },
    {
        id: 'logout',
        label: 'logout',
        component: LogOut,
        public: true,
        icon: faSignOutAlt,
        navPosition: 'footer',
        authenticatedOnly: true,
    },
];

const pageById = new Map(Pages.map((page) => [page.id, page]));

export class RouterModel {
    activePage = $state(window.location.pathname.slice(1));
    intendedPage = $state<string | null>(null);

    setActivePage(route: string, updateHistory = true) {
        // transient parse of the route, not reactive state, so plain URL is fine
        // eslint-disable-next-line svelte/prefer-svelte-reactivity
        const url = new URL(route, window.location.origin);
        this.activePage = url.pathname.slice(1);
        if (updateHistory) {
            const path = url.pathname + url.search;
            if (window.location.pathname + window.location.search !== path) {
                history.pushState(null, '', path);
            }
        }
    }

    setIntendedPage(page: string | null) {
        this.intendedPage = page;
    }

    // look up a page by its id
    getPageById(id: string): PageDefinition | undefined {
        return pageById.get(id);
    }

    // sidebar visibility, derived from the page access rules
    isPageVisible(page: PageDefinition, isLoggedIn: boolean): boolean {
        if (page.authenticatedOnly) {
            return isLoggedIn;
        }
        if (page.anonymousOnly) {
            return !isLoggedIn;
        }
        return page.public || isLoggedIn;
    }

    // the redirect target for a given auth state (null to stay put); isLoggedIn is
    // passed in so this stays pure and testable without touching Session
    getRedirectTarget(isLoggedIn: boolean): string | null {
        const page = this.getPageById(this.activePage);

        // unknown page: stay put, the app renders NotFound
        if (!page) {
            return null;
        }

        // anonymous user on a protected page: send to login
        // note: this discloses which protected routes exist; to hide them,
        // treat this case like an unknown page (return null to render NotFound)
        if (!page.public && !isLoggedIn) {
            return 'login';
        }

        // logged-in user on an anonymous-only page (home, login, register):
        // send to the intended page, defaulting to the dashboard
        if (page.anonymousOnly && isLoggedIn) {
            return this.intendedPage ?? 'dashboard';
        }

        return null;
    }
}

export const Router = new RouterModel();
