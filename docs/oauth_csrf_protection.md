# Understanding OAuth Security: Preventing CSRF Attacks

When building modern web applications with Single Sign-On (SSO) features like "Log in with Google," ensuring the security of the authentication flow is paramount. One of the most common threats to this flow is a Cross-Site Request Forgery (CSRF) attack.

This document explains what a CSRF attack is in the context of OAuth, how the OAuth flow works, and how our cookie-based approach safely mitigates this threat.

---

## 1. The Standard OAuth Flow (How it Should Work)

To understand the attack, we first need to understand the standard, safe flow when you log into a website (let's call it MyAwesomeApp) using Google.

1. **Initiation:** You go to myawesomeapp.com and click "Log in with Google."
2. **Redirect to Provider:** MyAwesomeApp redirects your browser to Google's login page (accounts.google.com). Hidden in this redirect URL is a request from MyAwesomeApp asking for permission to see your profile.
3. **Authentication:** You enter your credentials on Google's site and grant MyAwesomeApp permission.
4. **The Callback:** Google redirects your browser back to MyAwesomeApp (specifically, the `/api/auth/callback` endpoint). Crucially, Google includes a temporary "authorization code" in the URL.
5. **Token Exchange:** Behind the scenes, MyAwesomeApp takes that code and sends it directly to Google via a secure backchannel — a direct server-to-server call that never passes through your browser — and trades it for your actual profile information and access tokens. MyAwesomeApp now knows who you are and logs you in.

---

## 2. The CSRF Attack: "Login Forgery"

### What is CSRF?

A Cross-Site Request Forgery (CSRF) attack is a technique where an attacker tricks your browser into making a request that you never intended to make. The key insight is that browsers automatically attach cookies and credentials to requests, even when those requests are triggered by a completely different website you happen to be visiting. The attacker doesn't need to steal your password or break any encryption — they just need to get your browser to fire off the right request at the right moment.

In the context of OAuth, the attack doesn't try to steal your username or password. Instead, it attempts to trick your browser into completing *someone else's* login flow — silently logging you into the attacker's account on MyAwesomeApp without you realising it.

### How the Attack Works

1. **The Attacker Prepares:** An attacker goes to myawesomeapp.com and starts the "Log in with Google" flow themselves using their own Google account. They go through steps 1, 2, and 3 above. Then — right when Google redirects them back to MyAwesomeApp with their authorization code (Step 4) — they intercept and stop the request before it completes. They now have a valid callback URL containing an authorization code that, if completed, would log a browser into *their* (the attacker's) account.
2. **The Trap:** The attacker embeds this intercepted URL into a malicious website (e.g., freemoney.com) or sends it to you in an email. It might be disguised as an image, a button, or even an invisible element that loads automatically when you open the page — no click required.
3. **The Victim Triggers It:** You visit freemoney.com or open the email. Your browser automatically makes a request to the URL the attacker embedded — potentially without you clicking anything at all.
4. **The Unintended Login:** The URL your browser just requested is MyAwesomeApp's callback endpoint, containing the attacker's authorization code. MyAwesomeApp receives it, exchanges the code with Google, gets back the attacker's profile, and logs *your browser* into the attacker's account. You are now unknowingly signed in as the attacker.

### Why This Is Dangerous

This may sound abstract, so here are concrete examples of the harm it can cause:

- **E-commerce sites:** You are now logged into the attacker's account without knowing it. You browse the store, add items to the cart, and check out — entering your credit card number. The purchase is made on the attacker's account. They receive the order confirmation, the shipping notification, and potentially have your saved payment details stored on their profile.
- **Search or history-tracking sites:** Everything you search for, read, or interact with is recorded against the attacker's account. They log in later and can see your full activity history.
- **Account takeover via account linking:** This is the most dangerous scenario. Suppose MyAwesomeApp lets you link a social login (like Google) to an existing native account (one with a username and password). An attacker could trick you into linking *their* Google account to *your* existing MyAwesomeApp account. From that point on, the attacker can log into your account — with all your data, saved settings, and history — simply by signing in with their own Google account.
- **Phishing and trust abuse:** If you are logged into the attacker's account and contact customer support, fill in a form, or submit sensitive information, all of that goes to the attacker's profile. You have no reason to suspect anything is wrong.

In every case, the attack is especially insidious because nothing looks broken from your perspective. The site works normally — you just happen to be using someone else's account.

---

## 3. The Solution: The `state` Parameter

To prevent this, the OAuth specification introduced the `state` parameter. It acts as a secret handshake between your browser and MyAwesomeApp to prove that the person *finishing* the login is the exact same person who *started* it.

### The Secure Flow

1. **Initiation (The Handshake Begins):** When you click "Log in with Google," MyAwesomeApp generates a long, random, unguessable string (e.g., `xyz123`). This is the state token.
2. **Send and Save:**
   - MyAwesomeApp includes this state token in the redirect URL to Google (`...?state=xyz123`).
   - MyAwesomeApp also needs to remember this token so it can check it later. Rather than storing it on the server, it sends the token to *your browser* as a secure, temporary cookie named `oauth_state`. This is intentional — we'll explain why below.
3. **The Callback (Verifying the Handshake):** You log in on Google. When Google redirects you back to MyAwesomeApp, it is required by the OAuth specification to pass back the exact same `state` value it received (`...?code=abc&state=xyz123`).
4. **The Check:** Your browser arrives at MyAwesomeApp's callback endpoint carrying two things:
   - The `state` value returned by Google as a query parameter in the URL (`xyz123`).
   - The `oauth_state` cookie that MyAwesomeApp set in step 2 (also `xyz123`).

   MyAwesomeApp compares the two. If they match, it knows this callback was initiated by the same browser that started the flow, and the login proceeds.

### Why This Defeats the Attacker

Let's replay the attack with the `state` parameter in place:

1. The attacker starts the login on their own machine. MyAwesomeApp generates `state=badguy99` and sets an `oauth_state=badguy99` cookie in the attacker's browser. The attacker intercepts the callback URL: `...?code=evilCode&state=badguy99`.
2. The attacker tricks you into triggering that URL.
3. Your browser makes the request to MyAwesomeApp's callback endpoint.
4. **The defence kicks in:** MyAwesomeApp reads `state=badguy99` from the URL. It then checks your browser: "Do you have an `oauth_state` cookie that matches this?"
5. **The attack fails:** Because you never initiated a login on your own machine, your browser has no `oauth_state` cookie — or if you happened to start a separate login, your cookie contains a completely different random value. The values don't match. MyAwesomeApp recognises this as a forged request, rejects it, and you remain safe.

The reason cookies work so well here is precisely because of their browser-scoping rules: a cookie set by MyAwesomeApp on your browser can only be read by your browser when visiting MyAwesomeApp. An attacker on a different machine cannot access your cookies, and they cannot forge a cookie on your browser to match their intercepted state value.

---

## 4. Our Implementation Details

In our specific Rust/Svelte implementation, we take this standard approach and add several additional layers of protection:

- **Statelessness via JWTs:** Instead of storing a raw random string in the cookie, we package the state value — along with useful metadata such as the page you were trying to access before being prompted to log in — into a JSON Web Token (JWT). This JWT is cryptographically signed before being placed in the cookie.
- **Tamper-Proof:** Because the cookie is signed, an attacker cannot modify its contents to match a forged URL. Any tampering causes the cryptographic signature check to fail immediately, and the request is rejected.
- **`HttpOnly` and `Secure` flags:** The `oauth_state` cookie is marked `HttpOnly` (so malicious JavaScript running on the page cannot read it) and `Secure` (so it is only transmitted over encrypted HTTPS connections, preventing interception on the network).
- **Automatic Cleanup:** Once the login flow completes — whether it succeeds or fails — we immediately instruct the browser to delete the temporary `oauth_state` cookie by setting `Max-Age: 0`. This ensures no stale state lingers in the browser.

By combining signed JWT cookies, strict cookie flags, and automatic cleanup, our implementation ensures that every login flow is genuine, tamper-proof, and fully protected against Cross-Site Request Forgery.