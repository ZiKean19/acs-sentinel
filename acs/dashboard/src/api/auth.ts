// src/api/auth.ts — Cognito authentication
//
// Two sign-in paths, one session:
//
//   1. Password — amazon-cognito-identity-js, USER_PASSWORD_AUTH. Retained as
//      a break-glass control: if the external IdP, its consent screen, or the
//      hosted UI is unavailable, an operator must still be able to reach the
//      console. Standard emergency-access practice.
//
//   2. Google — OAuth 2.0 authorization code flow with PKCE (RFC 7636) against
//      the Cognito hosted UI. Authorisation is NOT granted by Google: the
//      PreSignUp Lambda allowlist decides whether an identity may be
//      provisioned at all. Google only proves who someone is.
//
// amazon-cognito-identity-js has no OAuth support whatsoever, so the Google
// path is implemented directly here. Rather than maintaining a second token
// store, the OAuth tokens are written into the exact localStorage keys the SDK
// reads from. getCurrentUser(), getSession(), silent refresh and getIdToken()
// then behave identically for both paths — api/client.ts needs no changes.

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserSession,
} from 'amazon-cognito-identity-js'

const USER_POOL_ID = import.meta.env.VITE_COGNITO_USER_POOL_ID as string
const CLIENT_ID = import.meta.env.VITE_COGNITO_CLIENT_ID as string
// e.g. https://acs-sentinel-tp070370.auth.ap-southeast-1.amazoncognito.com
const HOSTED_UI = ((import.meta.env.VITE_COGNITO_DOMAIN as string) ?? '').replace(/\/+$/, '')

// Must match a CallbackURL registered on the app client exactly, including the
// trailing slash — Cognito compares by string, not by URL semantics.
const REDIRECT_URI = `${window.location.origin}/`

const VERIFIER_KEY = 'acs.pkce.verifier'
const STATE_KEY = 'acs.oauth.state'
const SDK_PREFIX = `CognitoIdentityServiceProvider.${CLIENT_ID}`

const userPool = new CognitoUserPool({
  UserPoolId: USER_POOL_ID,
  ClientId: CLIENT_ID,
})

let currentUser: CognitoUser | null = null

/* ══════════════════════════════════════════════════════════════════════════
   Password path — break-glass
   ══════════════════════════════════════════════════════════════════════════ */

export function signIn(username: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: username, Pool: userPool })
    // The app client is configured for USER_PASSWORD_AUTH (not SRP), so tell
    // the SDK to use that flow explicitly — otherwise it defaults to
    // USER_SRP_AUTH and Cognito rejects it.
    user.setAuthenticationFlowType('USER_PASSWORD_AUTH')

    const authDetails = new AuthenticationDetails({ Username: username, Password: password })

    user.authenticateUser(authDetails, {
      onSuccess: () => {
        currentUser = user
        resolve()
      },
      onFailure: (err) => {
        reject(new Error(err.message || 'Authentication failed'))
      },
      newPasswordRequired: () => {
        reject(new Error('Password reset required — contact administrator'))
      },
    })
  })
}

/* ══════════════════════════════════════════════════════════════════════════
   PKCE helpers
   ══════════════════════════════════════════════════════════════════════════ */

function b64url(bytes: Uint8Array): string {
  let s = ''
  bytes.forEach((b) => { s += String.fromCharCode(b) })
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomToken(byteLength = 32): string {
  const buf = new Uint8Array(byteLength)
  crypto.getRandomValues(buf)
  return b64url(buf)
}

async function s256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return b64url(new Uint8Array(digest))
}

function decodeJwtPayload(token: string): Record<string, any> {
  const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(b64)
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes))
}

function stripQueryString() {
  window.history.replaceState({}, document.title, window.location.pathname)
}

/* ══════════════════════════════════════════════════════════════════════════
   Google path — OAuth 2.0 authorization code + PKCE
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Redirects to Google. Never returns — the browser navigates away.
 *
 * identity_provider=Google makes Cognito forward straight to Google instead of
 * rendering its own unbranded chooser, so the operator only ever sees this
 * dashboard and Google.
 */
export async function signInWithGoogle(): Promise<void> {
  if (!HOSTED_UI) throw new Error('VITE_COGNITO_DOMAIN is not configured.')

  const verifier = randomToken(32)
  const state = randomToken(16)

  // sessionStorage, not localStorage: these are single-use, tab-scoped, and
  // must not outlive the redirect.
  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)

  const params = new URLSearchParams({
    identity_provider: 'Google',
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile',
    state,
    code_challenge: await s256(verifier),
    code_challenge_method: 'S256',
  })

  window.location.assign(`${HOSTED_UI}/oauth2/authorize?${params.toString()}`)
}

let redirectPromise: Promise<boolean> | null = null

/**
 * Call once on app boot. Returns true if a Google redirect was consumed and a
 * session established; false if this is an ordinary page load.
 *
 * Throws with a human-readable message when the IdP or the allowlist rejected
 * the sign-in — including the PreSignUp denial, which Cognito surfaces here as
 * error_description.
 *
 * Idempotent by design. React StrictMode double-invokes effects in
 * development, and the first call consumes ?code=, clears the PKCE verifier
 * and strips the query string — so a naive second call would find nothing,
 * report "not signed in", and drop the user back on the login screen while the
 * first token exchange was still in flight. Caching the promise means every
 * caller observes the same outcome, and the single-use authorization code is
 * never redeemed twice (Cognito rejects a replay with invalid_grant).
 */
export function completeOAuthRedirect(): Promise<boolean> {
  if (!redirectPromise) redirectPromise = consumeOAuthRedirect()
  return redirectPromise
}

async function consumeOAuthRedirect(): Promise<boolean> {
  const params = new URLSearchParams(window.location.search)
  const error = params.get('error')
  const code = params.get('code')

  if (error) {
    const description = params.get('error_description') || error
    stripQueryString()
    sessionStorage.removeItem(VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
    throw new Error(decodeURIComponent(description.replace(/\+/g, ' ')))
  }

  if (!code) return false

  const returnedState = params.get('state')
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(VERIFIER_KEY)

  sessionStorage.removeItem(VERIFIER_KEY)
  sessionStorage.removeItem(STATE_KEY)
  stripQueryString()

  // CSRF defence: a code delivered without the state we issued did not come
  // from a flow this tab started.
  if (!expectedState || returnedState !== expectedState) {
    throw new Error('Sign-in could not be verified. Please try again.')
  }
  if (!verifier) {
    throw new Error('Sign-in session expired. Please try again.')
  }

  // Public client (no secret in a browser bundle), so PKCE is what proves this
  // is the same client that began the flow.
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  })

  const res = await fetch(`${HOSTED_UI}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })

  if (!res.ok) {
    throw new Error('Could not complete Google sign-in. Please try again.')
  }

  storeFederatedSession(await res.json())
  return true
}

/**
 * Adopt the OAuth tokens into amazon-cognito-identity-js's own storage layout.
 *
 * These key names are the SDK's internal contract. Writing them directly is
 * deliberate: it means one session model for both sign-in paths, and the
 * existing getIdToken() keeps working — including silent refresh, since the
 * app client allows ALLOW_REFRESH_TOKEN_AUTH.
 */
function storeFederatedSession(tokens: {
  id_token: string
  access_token: string
  refresh_token?: string
}) {
  const claims = decodeJwtPayload(tokens.id_token)
  const username: string = claims['cognito:username'] ?? claims.sub

  const drift = Math.floor(Date.now() / 1000) - Number(claims.iat ?? 0)

  localStorage.setItem(`${SDK_PREFIX}.LastAuthUser`, username)
  localStorage.setItem(`${SDK_PREFIX}.${username}.idToken`, tokens.id_token)
  localStorage.setItem(`${SDK_PREFIX}.${username}.accessToken`, tokens.access_token)
  if (tokens.refresh_token) {
    localStorage.setItem(`${SDK_PREFIX}.${username}.refreshToken`, tokens.refresh_token)
  }
  localStorage.setItem(`${SDK_PREFIX}.${username}.clockDrift`, String(Number.isFinite(drift) ? drift : 0))

  currentUser = null // force the next getIdToken() to re-read from storage
}

/* ══════════════════════════════════════════════════════════════════════════
   Session
   ══════════════════════════════════════════════════════════════════════════ */

/**
 * Current valid ID token (JWT), refreshing the session if needed.
 * Null if not signed in or the session cannot be restored.
 */
export function getIdToken(): Promise<string | null> {
  return new Promise((resolve) => {
    const user = currentUser ?? userPool.getCurrentUser()
    if (!user) {
      resolve(null)
      return
    }
    user.getSession((err: Error | null, session: CognitoUserSession | null) => {
      if (err || !session || !session.isValid()) {
        resolve(null)
        return
      }
      currentUser = user
      resolve(session.getIdToken().getJwtToken())
    })
  })
}

export function isAuthenticated(): Promise<boolean> {
  return getIdToken().then((t) => t !== null)
}

/** True when the active session was established through an external IdP. */
export function isFederatedSession(): boolean {
  return (localStorage.getItem(`${SDK_PREFIX}.LastAuthUser`) ?? '').startsWith('Google_')
}

export function signOut(): void {
  const federated = isFederatedSession()

  const user = currentUser ?? userPool.getCurrentUser()
  if (user) user.signOut()
  currentUser = null

  // A federated session also holds a Cognito session cookie on the hosted UI
  // domain. Clearing localStorage alone would leave it intact, so the next
  // "Continue with Google" would silently re-authenticate with no prompt —
  // wrong for a console that may be shared between operators, and wrong for a
  // demo where the examiner expects sign-out to mean signed out.
  if (federated && HOSTED_UI) {
    const params = new URLSearchParams({ client_id: CLIENT_ID, logout_uri: REDIRECT_URI })
    window.location.assign(`${HOSTED_UI}/logout?${params.toString()}`)
  }
}
