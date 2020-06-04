# Example for Google Authentication
1. Navigate to [Google APIs Developer Console](https://console.developers.google.com/apis/dashboard)
2. Open Credentials
3. Click on `Create Credentials` and `OAuth client ID`
4. Select Application type `Web Application`
5. Enter as Authorised redirect URI `auth.yourdomain.tld/auth/resp`
6. Copy and save `Client Id` and `Client Secret`
    - e.g. `******.apps.googleusercontent.com` and `uqE8NtQQZ_******`
7. Configure the environment variables to the following:
    ```
    ISSUER=https://accounts.google.com
    CLIENT_ID=******.apps.googleusercontent.com
    CLIENT_SECRET=uqE8NtQQZ_******
    AUTH_DOMAIN=auth.yourdomain.tld
    COOKIE_DOMAIN=yourdomain.tld
    ```
8. Create the traefik forwardauth middleware (middlewares.forwardauth.toml):
    ```
    http:
    middlewares:
      keycloak:
      forwardAuth:
        address: "http://traefik-forward-auth:4181" # Note: You need to use the internal DNS name (e.g. docker container nmae)
        trustForwardHeader: true
        authResponseHeaders: [ "X-Forwarded-User" ]
    ```
9. Final docker-compose:
    ````yaml
    traefik:
      image: traefik:latest
      networks:
        - traefik
      volumes:
        - /var/run/docker.sock:/var/run/docker.sock:ro
        - ./config:/etc/traefik
      ports:
        - 80:80
        - 443:443
      restart: always

    whoami:
      image: containous/whoami
      networks:
        - traefik
      labels:
        # Docker
        - traefik.enable=true

        # Routing
        - traefik.http.routers.whoami.rule=Host(`whoami.yourdomain.tld`)
        - traefik.http.routers.whoami.tls.certresolver=letsencrypt
        - traefik.http.routers.whoami.tls.domains[0].main=*.yourdomain.tld
        - traefik.http.routers.whoami.tls.domains[0].sans=yourdomain.tld
        - traefik.http.routers.whoami.entrypoints=https
        - traefik.http.routers.whoami.middlewares=keycloak@file

        # Healthcehck
        - traefik.http.services.whoami.loadbalancer.server.port=80
        - traefik.http.services.whoami.loadbalancer.healthcheck.path=/
        - traefik.http.services.whoami.loadbalancer.healthcheck.interval=5s
        - traefik.http.services.whoami.loadbalancer.healthcheck.timeout=3s
      restart: always

    traefik-forward-auth:
      image: stivik/oidc-forward-auth
      networks:
        - traefik
      environment:
        - ISSUER=https://accounts.google.com
        - CLIENT_ID=******.apps.googleusercontent.com
        - CLIENT_SECRET=uqE8NtQQZ_******
        - AUTH_DOMAIN=auth.yourdomain.tld
        - COOKIE_DOMAIN=yourdomain.tld
        - LOG_LEVEL=debug
      labels:
        # Docker
        - traefik.enable=true

        # Routing
        - traefik.http.routers.keycloak-forward.rule=Host(`auth.yourdomain.tld`)
        - traefik.http.routers.keycloak-forward.tls.certresolver=letsencrypt
        - traefik.http.routers.keycloak-forward.tls.domains[0].main=*.yourdomain.tld
        - traefik.http.routers.keycloak-forward.tls.domains[0].sans=yourdomain.tld
        - traefik.http.routers.keycloak-forward.entrypoints=https
        - traefik.http.routers.keycloak-forward.middlewares=rate-limit@file
        - traefik.http.services.keycloak-forward.loadbalancer.server.port=4181
        - traefik.http.routers.keycloak-forward.middlewares=keycloak@file # Note: The forwardauth handler itself requires the forwardauth middleware
    ````
10. When you now browse to `whoami.yourdomain.tld` you will be redirected to the Google Auth and after successfully authentication you will be redirected back to the application.