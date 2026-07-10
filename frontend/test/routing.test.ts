import { describe, expect, it } from 'vitest';

import { RouterModel } from '../src/Router.svelte';

describe('getRedirectTarget', () => {
    // fresh instance per case so the tests stay hermetic and parallel-safe
    const redirect = (
        activePage: string,
        isLoggedIn: boolean,
        intendedPage: string | null = null
    ) => {
        const router = new RouterModel();
        router.activePage = activePage;
        router.intendedPage = intendedPage;
        return router.getRedirectTarget(isLoggedIn);
    };

    it('sends an anonymous user from a protected page to login', () => {
        expect(redirect('settings', false)).toBe('login');
        expect(redirect('dashboard', false)).toBe('login');
    });

    it('keeps an anonymous user on public pages', () => {
        expect(redirect('', false)).toBeNull();
        expect(redirect('about', false)).toBeNull();
        expect(redirect('login', false)).toBeNull();
        expect(redirect('register', false)).toBeNull();
    });

    it('keeps a logged-in user on regular pages', () => {
        expect(redirect('dashboard', true)).toBeNull();
        expect(redirect('settings', true)).toBeNull();
    });

    it('sends a logged-in user from login to the intended page', () => {
        expect(redirect('login', true, 'settings')).toBe('settings');
    });

    it('sends a logged-in user from anonymous-only pages to the dashboard', () => {
        expect(redirect('', true)).toBe('dashboard');
        expect(redirect('login', true)).toBe('dashboard');
        expect(redirect('register', true)).toBe('dashboard');
    });

    it('stays on an unknown page so the app renders NotFound', () => {
        expect(redirect('does-not-exist', true)).toBeNull();
        expect(redirect('does-not-exist', false)).toBeNull();
    });
});

describe('RouterModel.setActivePage', () => {
    it('accepts routes with or without a leading slash', () => {
        const router = new RouterModel();
        router.setActivePage('settings');
        expect(router.activePage).toBe('settings');
        expect(window.location.pathname).toBe('/settings');

        router.setActivePage('/about');
        expect(router.activePage).toBe('about');
        expect(window.location.pathname).toBe('/about');
    });

    it('preserves the query string in the browser url', () => {
        const router = new RouterModel();
        router.setActivePage('/settings?tab=profile');
        expect(router.activePage).toBe('settings');
        expect(window.location.pathname).toBe('/settings');
        expect(window.location.search).toBe('?tab=profile');
    });

    it('does not touch history when updateHistory is false', () => {
        const router = new RouterModel();
        router.setActivePage('/about');
        router.setActivePage('secure', false);
        expect(router.activePage).toBe('secure');
        expect(window.location.pathname).toBe('/about');
    });
});
