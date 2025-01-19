# Practice Go JWT authentication

This is a simple project that provides a protected endpoint that requires a valid JWT. It was my first time writing Go
and was created as a practice project prior to using Go to write a custom authoriser for an AWS API Gateway. The project
uses:

- [github.com/golang-jwt/jwt](https://github.com/golang-jwt/jwt) to parse and validate the JWT
- [github.com/MicahParks/keyfunc](https://github.com/MicahParks/keyfunc) to provide a `jwt.Keyfunc` for the above that
  fetches the JWKs from a JWKS
  endpoint
- [github.com/MicahParks/jwkset](https://github.com/MicahParks/jwkset) to generate and fetch the JWKs from a JWKS
  endpoint

## Overview

- This application is a simple Go server that provides:
    - `POST` `/register` - Register a new user with a username and password
    - `POST` `/login` - Login with a username and password to receive a JWT
    - `POST` `/protected` - A protected endpoint that requires a valid JWT
    - `GET` `/.well-known/jwks.json` - The JWKS endpoint called when validating JWTs
    - `POST` `/logout` - Logout and remove the JWT
- The server uses a simple in-memory store (no caching) for the users and JWKS
- On startup, the application generates a new key pair
- A basic middleware layer is used basic request logging and panic recovery
- A preconfigured Postman collection is provided in the `assets/postman` directory

## Configuration

The application will look for the following environment variables:

- `JWKS_BASE_URL` - default: `http://localhost:8080`, will append `/.well-known/jwks.json` to fetch the JWKS
- `JWK_PRIVATE_KEY` - the private key to sign the JWTs; must be one of the following:
    - The path to a PEM file containing the private key (e.g. `path/to/private.pem`)
    - The private key itself in PEM format
    - Empty or not provided to generate a new key pair on startup

## How to develop

### Using Nix

If you have direnv installed, use `direnv allow` to start a simple development shell.