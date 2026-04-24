/// <reference types="svelte" />
/// <reference types="vite/client" />

interface Window {
    __INITIAL_STATE__?: {
        user?: {
            id: string | number;
            email: string;
            tenant_id: number;
        };
    };
}
