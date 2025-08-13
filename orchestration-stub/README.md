# Orchestration Stub

## Running Locally

There are two ways of running the stub locally, depending on the purpose of the testing.
When testing AWS integrations with deployed auth environments, you can use SAM local.
For running a complete stack locally, an express server is run in a docker container.

### SAM Local

```bash
sam build && sam local start-api --parameter-overrides 'Environment=local'
```

Live reload

```bash
sam build
```

To generate keypair:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
openssl pkcs8 -topk8 -in private.ec.key -out private.pem -nocrypt
openssl ec -in private.pem -pubout -out public.pem
```

Then the private key is in private.pem (this goes into secrets manager) and the public is in public.pem
(configure the auth frontend and auth external API with this). Do not commit these files.

### Docker local

The `Dockerfile` runs a small express server which simulates the API Gateway interface.

If you are using the local running configuration in `authentication-api` then the configuration
should be supplied automatically through `.env.local`.

If running standalone, you need to provide the environment variable configuration yourself:

- `AUTHENTICATION_BACKEND_URL` - base URL for the auth /token and /userinfo endpoints
- `AUTHENTICATION_FRONTEND_URL` - base URL for the auth frontend
- `AUTH_PUB_KEY` - public key used for encrypting JAR payloads to auth
- `COOKIE_DOMAIN` - cookie domain, or `none` to use the default
- `PRIVATE_KEY` - private key used for signing JAR payloads and private-key-jwt auth
- `RP_CLIENT_ID` - RP client ID to pass to auth (not the orchestration client id)
- `RP_SECTOR_HOST` - RP sector host to pass to auth
- `STUB_URL` - URL of the stub itself, used to generate the callback, typically `http://localhost:4400/`

## Deploying

authdev1, authdev2 and build in [samconfig.toml](samconfig.toml) correspond to stubs that integrate with old frontend instances, predating Secure Pipelines. In the [template.yaml](template.yaml) mapping, these environments configurations are prefixed with "old-". To build and deploy, run the following command:

```bash
sam build && sam deploy --config-env <env>
```

To deploy stubs that integrate with secure pipelines deployed frontend instances, use GitHub workflow [Build and deploy Orchestration stub](https://github.com/govuk-one-login/authentication-stubs/actions/workflows/build-deploy-orch-stub-sp.yaml) instead.
