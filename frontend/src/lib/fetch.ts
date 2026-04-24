async function handleResponse(res: Response): Promise<any> {
    const contentType = res.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
        return await res.json();
    } else {
        const text = await res.text();
        try {
            // try to parse as JSON anyway, in case content-type is missing
            return JSON.parse(text);
        } catch {
            // return as an object with the text as message
            return { result: res.ok ? "ok" : "error", message: text || res.statusText };
        }
    }
}

export async function getApi(api_token?: string): Promise<any> {
    const headers: Record<string, string> = {
        "Accept": "application/json",
    };

    if (api_token) {
        headers["Authorization"] = "Bearer " + api_token;
    }

    // if no token is provided, fetch expects the browser to use session cookies
    const options: RequestInit = { headers };
    if (!api_token) {
        options.credentials = 'same-origin';
    }

    const res = await fetch('/api', options);
    return await handleResponse(res);
}

export async function getHealth(): Promise<any> {
    const res = await fetch('/api/health');
    return await handleResponse(res);
}
