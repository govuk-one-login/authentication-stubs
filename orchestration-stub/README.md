# Orchestration Stub

## Running Locally

```bash
sam build && docker compose up --detach && sam local start-api --docker-network lambda-local --parameter-overrides 'Environment=local'
```

Live reload

```bash
sam build
```

Redis passwords containing special characters should be URL encoded

To generate keypair:

```bash
openssl ecparam -name prime256v1 -genkey -noout -out private.ec.key
openssl pkcs8 -topk8 -in private.ec.key -out private.pem -nocrypt
openssl ec -in private.pem -pubout -out public.pem
```

Then the private key is in private.pem (this goes into secrets manager) and the public is in public.pem
(configure the auth frontend and auth external API with this). Do not commit these files.

## Deploying

authdev1, authdev2 and build in [samconfig.toml](samconfig.toml) correspond to stubs that integrate with old frontend instances, predating Secure Pipelines. In the [template.yaml](template.yaml) mapping, these environments configurations are prefixed with "old-". To build and deploy, run the following command:

```bash
sam build && sam deploy --config-env <env>
```

To deploy stubs that integrate with secure pipelines deployed frontend instances, use GitHub workflow [Build and deploy Orchestration stub](https://github.com/govuk-one-login/authentication-stubs/actions/workflows/build-deploy-orch-stub-sp.yaml) instead.
