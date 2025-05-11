export async function getSecure() {
    let res = await fetch('/secure',{credentials: 'same-origin'});
    let secureResponse = await res.json();
    return JSON.stringify(secureResponse.session);
}

export async function getApi(api_token: string): Promise<any> {
    let headers = {
        Authorization: "Bearer " + api_token,
        Accept: "application/json",
    };
    return await fetch('/api', { headers }).then(r => r.json());
}