# Notify Stub

Stub implementation of GOV.UK Notify API for testing authentication integrations.

## Running Locally

### Prerequisites
- Node.js 24
- AWS SAM CLI
- Docker (for LocalStack DynamoDB)

### Start LocalStack

```bash
cd localstack
docker-compose up -d
cd ..
```

### Run

```bash
npm install
npm run start:local
```

The API will be available at `http://localhost:3000`.

## Endpoints

- `GET /` - View notifications (HTML)
- `POST /v2/notifications/email` - Send email notification
- `POST /v2/notifications/sms` - Send SMS notification
