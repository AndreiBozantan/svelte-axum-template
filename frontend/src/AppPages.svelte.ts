import About from './pages/About.svelte';
import Home from './pages/Home.svelte';
import LogIn from './pages/Login.svelte';
import LogOut from './pages/Logout.svelte';
import SecureApi from './pages/SecureApi.svelte';
import Settings from './pages/Settings.svelte';
import { AppState } from '$lib/AppState.svelte';
import { wrap, type WrappedComponent } from 'svelte-spa-router/wrap';
import type { Component } from 'svelte';
import type { IconDefinition } from '@fortawesome/fontawesome-svg-core';
import {
    faSignOutAlt,
    faCog,
    faSignInAlt,
    faHome,
    faCheckCircle,
    faInfoCircle,
} from '@fortawesome/free-solid-svg-icons';

type VisibilityFn = () => boolean;

export type PageDefinition = {
    id: string;
    label: string;
    component: Component;
    public: boolean;
    icon: IconDefinition;
    navPosition?: 'top' | 'footer' | 'none';
    visible: VisibilityFn;
};

export const Pages: PageDefinition[] = [
    {
        id: '',
        label: 'home',
        component: Home,
        public: false,
        icon: faHome,
        navPosition: 'top',
        visible: () => AppState.isLoggedIn,
    },
    {
        id: 'secure',
        label: 'secure api',
        component: SecureApi,
        public: false,
        icon: faCheckCircle,
        navPosition: 'top',
        visible: () => AppState.isLoggedIn,
    },
    {
        id: 'about',
        label: 'about',
        component: About,
        public: true,
        icon: faInfoCircle,
        navPosition: 'top',
        visible: () => true,
    },
    {
        id: 'settings',
        label: 'settings',
        component: Settings,
        public: false,
        icon: faCog,
        navPosition: 'footer',
        visible: () => AppState.isLoggedIn,
    },
    {
        id: 'login',
        label: 'login',
        component: LogIn,
        public: true,
        icon: faSignInAlt,
        navPosition: 'footer',
        visible: () => !AppState.isLoggedIn,
    },
    {
        id: 'logout',
        label: 'logout',
        component: LogOut,
        public: true,
        icon: faSignOutAlt,
        navPosition: 'footer',
        visible: () => AppState.isLoggedIn,
    },
];

// Dynamically generate the route map from the Pages array to avoid duplication
export const routes: Record<string, Component | WrappedComponent> = Object.fromEntries(
    Pages.map((page) => {
        const path = page.id === '' ? '/' : `/${page.id}`;

        if (page.public) {
            return [path, page.component];
        }

        return [
            path,
            wrap({
                component: page.component,
                conditions: [() => AppState.isLoggedIn],
            }),
        ];
    })
);

// Fallback (404 / catch-all) route: redirect to Home if logged in, otherwise to About if public
routes['*'] = wrap({
    component: Home,
    conditions: [() => AppState.isLoggedIn],
});
