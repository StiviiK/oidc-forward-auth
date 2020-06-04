# OIDC Forward Auth for Traefik (v2+)
An OIDC compliant traefik forward auth handler which follows the lifecycle of the token, also supports refreshing of tokens (WIP).
Supports all OIDC compliant Identity Solutions, e.g. KeyCloak, GitHub, Google, ...

# Configuration
Configuration is currently only via environmnet variables supported:
|Environment Variable   |Type  |Description|Example|
|-----------------------|------|-----------|-------|
|ISSUER|string|OIDC Issuer (required)|https://accounts.google.com|
|CLIENT_ID|string|OIDC Client Id (required)|CLIENT_ID|
|CLIENT_SECRET|string|OIDC Client Secret (required)|CLIENT_SECRET|
|AUTH_DOMAIN|string|Central auth domain (required)|auth.example.com|
|COOKIE_DOMAIN|string|Root domain(s) of protected host(s) (required)|example.com|


# Usage
The authenticated user is set in the `X-Forwarded-User` header.
See more in the Example section.

# Future Features
- Refresh Token support 
- Add option to only allow Users with verfied Mails    
- Add Mail whitelist, also domain based    

# Cookie Domains
You can supply a comma separated list of cookie domains, if the host of the original request is a subdomain of any given cookie domain, the authentication cookie will set with the given domain.

For example, if cookie domain is test.com and a request comes in on app1.test.com, the cookie will be set for the whole test.com domain. As such, if another request is forwarded for authentication from app2.test.com, the original cookie will be sent and so the request will be allowed without further authentication.

# Operation Details
For example, you have a few applications: app1.test.com, app2.test.com, appN.test.com. To utilise an auth host, permit domain level cookies by setting the cookie domain to test.com then set the auth-host to: auth.test.com.

The user flow will then be:

1. Request to app10.test.com/home/page
2. User redirected to OIDC login
3. After OIDC login, user is redirected to auth.test.com/auth/resp
4. Token, user and CSRF cookie is validated, auth cookie is set to test.com
5. User is redirected to app10.test.com/home/page
6. Request is allowed

Two criteria must be met for an auth-host to be used:

1. Request matches given cookie-domain
2. auth-host is also subdomain of same cookie-domain