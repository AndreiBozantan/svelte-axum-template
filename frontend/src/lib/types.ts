export interface User {
    id: number;
    email: string;
    tenant_id: number;
}

export interface ApiErrorResponse {
    code: string;
    message: string;
}
