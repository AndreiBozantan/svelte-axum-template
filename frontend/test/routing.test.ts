import { describe, expect, it } from 'vitest';

import { AppState } from '$lib/AppState.svelte';
import { resolveRedirect } from '../src/AppPages.svelte';

describe('resolveRedirect', () => {
    it('redirects an anonymous user from a protected page to login', () => {
        expect(resolveRedirect('settings', false, null)).toBe('login');
        expect(resolveRedirect('', false, null)).toBe('login');
    });

    it('keeps an anonymous user on public pages', () => {
        expect(resolveRedirect('about', false, null)).toBeNull();
        expect(resolveRedirect('login', false, null)).toBeNull();
    });

    it('keeps a logged-in user on regular pages', () => {
        expect(resolveRedirect('', true, null)).toBeNull();
        expect(resolveRedirect('settings', true, null)).toBeNull();
    });

    it('redirects a logged-in user from login to the intended page', () => {
        expect(resolveRedirect('login', true, 'settings')).toBe('settings');
    });

    it('redirects a logged-in user from login to home when there is no intended page', () => {
        expect(resolveRedirect('login', true, null)).toBe('');
    });

    it('redirects an unknown page to home when logged in, otherwise to about', () => {
        expect(resolveRedirect('does-not-exist', true, null)).toBe('');
        expect(resolveRedirect('does-not-exist', false, null)).toBe('about');
    });
});

describe('AppState.setActivePage', () => {
    it('accepts routes with or without a leading slash', () => {
        AppState.setActivePage('settings');
        expect(AppState.activePage).toBe('settings');
        expect(window.location.pathname).toBe('/settings');

        AppState.setActivePage('/about');
        expect(AppState.activePage).toBe('about');
        expect(window.location.pathname).toBe('/about');
    });

    it('preserves the query string in the browser url', () => {
        AppState.setActivePage('/settings?tab=profile');
        expect(AppState.activePage).toBe('settings');
        expect(window.location.pathname).toBe('/settings');
        expect(window.location.search).toBe('?tab=profile');
    });

    it('does not touch history when updateHistory is false', () => {
        AppState.setActivePage('/about');
        AppState.setActivePage('secure', false);
        expect(AppState.activePage).toBe('secure');
        expect(window.location.pathname).toBe('/about');
    });
});
