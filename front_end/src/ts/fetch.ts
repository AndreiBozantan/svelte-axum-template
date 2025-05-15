import { getAccessToken } from './auth';

export async function getSecure() {
    let res = await fetch('/secure',{credentials: 'same-origin'});
    let secureResponse = await res.json();
    return JSON.stringify(secureResponse.session);
}

export async function getApi(api_token?: string): Promise<any> {
    // If no token is provided, try to get one from storage
    if (!api_token) {
        api_token = await getAccessToken() || '';
    }
    
    let headers = {
        Authorization: "Bearer " + api_token,
        Accept: "application/json",
    };
    return await fetch('/api', { headers }).then(r => r.json());
}

// Helper function to make authenticated API requests
export async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<any> {
    // Get the current access token
    const token = await getAccessToken();
    
    if (!token) {
        throw new Error('Not authenticated');
    }
    
    // Merge headers with authorization
    const headers = {
        ...options.headers,
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
    };
    
    // Make the request
    const response = await fetch(url, {
        ...options,
        headers,
    });
    
    // Handle 401 (unauthorized) responses
    if (response.status === 401) {
        throw new Error('Authentication failed');
    }
    
    return response.json();
}