# goLang-jwt-auth-example
This is an example implementation of jwt auth with goLang. Please note that I am not an expert in this field and am creating this repository more for a learning experience than anything else. I hope to learn a lot from this experience and am sharing my work so that you might learn, too.

Also, this isn't an exmaple of how to structure a web app or how to map and handle authorized / un-authorized routes, etc.

FYI - I'm using [goDep](https://github.com/tools/godep)

## Goals
It is important to understand the objective of this auth architecture. It certainly is not an applicable design for all use cases. Please read and understand the goals, below, and make changes to your own workflow to suit your specific needs.

1. Protection of non-critical api's (e.g. not meant for financial, healthcare, gov't, etc. services)
2. Stateless
3. User sessions
4. XSS protection
5. CSRF protection
6. Web (but could be easily modified for use in mobile / other. i.e. for native mobile don't use cookies but rather the proper, secure storage methods for your platform)

## Basics
The design of this auth system is based around the three major components, listed below.

1. Short-lived (minutes) JWT Auth Token
2. Longer-lived (hours / days) JWT Refresh Token
3. CSRF secret string

Once a user provides valid login credentials, they are sent back the three items listed above.

### 1. Short-lived (minutes) JWT Auth Token
The short-lived jwt auth token allows the user to make stateless requests to protected api endpoints and lives in an http only cookie on the client. It has an expiration time in minutes and will be refreshed by the longer-lived refresh token. This token contains the following claims:

* sub [uuid]: the subject (user) who has requested this claim.
* exp [timestamp]: the date/time the token expires (I'm using 15 minutes in this example. Adjust as you see fit)
* role [string]: One of "admin" or "user"
* csrf [string]: A random string to be used to protect against csrf attacks

### 2. Longer-lived (hours/days) JWT Refresh Token
This longer-lived token will be used to update the auth tokens. These tokens will also live in http only cookies on the client. These tokens have a 72 hour expiration time which will be updated each time an auth token is refreshed. If a client tries to use an expired refresh token, they will be re-directed to a login page. 

These refresh tokens contain an id which can be revoked by an authorized client.

The claims of this refresh token include:
* jti [uuid]: a unique string to identify this token
* sub [uuid]: the subject (userId) who has requested this claim.
* exp [timestamp]: the date/time the token expires (I'm using 72 hours in this example. Adjust as you see fit)

### 3. CSRF Secret String
A CSRF secret string will be provided to each client and will be identical the CSRF secret in the auth token and will change each time an auth token is refreshed. These secrets will live in an "X-CSRF-Token" response header. These secrets will be sent along with the auth and refresh tokens on each api request. They will be sent to the server either as a hidden form value or in the request header. This secret will be checked against the secret provided in the auth token in order to prevent CSRF attacks.


## Auth Flow
### Sign In
1. User provides a username and password
2. Password is SHA256 hashed on the client before being sent to the server (never simply rely on https and send plaintext passwords over the wire!!)
3. SHA256 password hash is bcrypted and checked against the database
4. If a match is found, an auth token, refresh token and CSRF secret is created and sent back to the client. The refresh token's JTI is stored in the db.
    * The auth token and refresh tokens are kept in http only cookies
    * The CSRF secret is sent in the response header, with a key of "X-CSRF-Token"

### Restricted API request
1. Client adds the CSRF token to the request header with the key "X-CSRF-Token" (can also be sent as a hidden form value)
2. The auth token is checked:
    * First, the csrf secret from the request header is matched to the secret in the auth jwt
    * Second, the token expiration time is checked:
        * If not expired, the request is allowed
        * If expired, a new auth token is issued from the refresh token. The refresh token expiration is checked, and the JTI checked against the db. If both checks pass, a new auth token is generated. If either check fails, the request fails and the user is asked to log back in.
3. Finally, if successful, a new csrf secret is generated and stored in the newly created auth token. Also, the refresh token expiration time is reset.
4. The auth token, refresh token and csrf secret are sent back to the client as described, above.

### Sign out
1. Signout is a restricted route, so the client must provide an auth token, refresh token and csrf secret. They are checked as described, above.
2. The refresh token JTI is removed from the whitelisted list of valid JTI's in our db
3. The client's auth and refresh tokens are nullified (their values are set to "")