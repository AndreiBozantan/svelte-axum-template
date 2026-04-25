export interface User {
    id: number;
    email: string;
    tenant_id: number;
}

export interface AuthResponse {
    result: 'ok' | 'error';
    user?: User;
    message?: string;
}
