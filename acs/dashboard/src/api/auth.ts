// src/api/auth.ts — Cognito authentication
//
// Uses amazon-cognito-identity-js to authenticate against the ACS Sentinel
// Cognito User Pool and obtain a JWT, which the API client attaches to every
// request. The dashboard API (API Gateway) validates this JWT via its Cognito
// authorizer before allowing access to /alerts, /blocked-ips, /logs.
//
// Install the dependency:  npm install amazon-cognito-identity-js

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserSession,
} from 'amazon-cognito-identity-js'

const USER_POOL_ID = import.meta.env.VITE_COGNITO_USER_POOL_ID as string
const CLIENT_ID    = import.meta.env.VITE_COGNITO_CLIENT_ID as string

const userPool = new CognitoUserPool({
  UserPoolId: USER_POOL_ID,
  ClientId:   CLIENT_ID,
})

let currentUser: CognitoUser | null = null

export function signIn(username: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: username, Pool: userPool })
    // The app client is configured for USER_PASSWORD_AUTH (not SRP), so tell
    // the SDK to use that flow explicitly — otherwise it defaults to
    // USER_SRP_AUTH and Cognito rejects it.
    user.setAuthenticationFlowType('USER_PASSWORD_AUTH')

    const authDetails = new AuthenticationDetails({
      Username: username,
      Password: password,
    })

    user.authenticateUser(authDetails, {
      onSuccess: () => {
        currentUser = user
        resolve()
      },
      onFailure: (err) => {
        reject(new Error(err.message || 'Authentication failed'))
      },
      // First-login "new password required" flow — the admin user was created
      // with a permanent password, so this normally won't fire, but handle it
      // gracefully just in case.
      newPasswordRequired: () => {
        reject(new Error('Password reset required — contact administrator'))
      },
    })
  })
}

/**
 * Returns the current valid ID token (JWT), refreshing the session if needed.
 * Returns null if the user isn't signed in or the session can't be restored.
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

export function signOut(): void {
  const user = currentUser ?? userPool.getCurrentUser()
  if (user) user.signOut()
  currentUser = null
}

export function isAuthenticated(): Promise<boolean> {
  return getIdToken().then((t) => t !== null)
}
