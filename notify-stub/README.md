# Notify Stub

Stub implementation of GOV.UK Notify API for testing authentication integrations.

## Running Locally

### Prerequisites
- Node.js 22 (use `nvm use`)
- AWS SAM CLI
- Docker (for LocalStack DynamoDB)

### Start LocalStack

```bash
cd localstack
docker-compose up -d
cd ..
```

### Build and Run

```bash
npm install
npm run build
npm run start:local
```

The API will be available at `http://localhost:3000`.

## Endpoints

- `POST /v2/notifications/email` - Send email notification
- `POST /v2/notifications/sms` - Send SMS notification

## Deploying

Use GitHub Actions workflows for deployment to dev/build environments.
