# AMC Stub

Authentication stub for AMC (Account Management Components) services. This stub will provide functionality for the
OAuth part of Authentication interactions with AMC, as well as provide functionality to interact with the Authentication
Account Management API for the SSAD flow (Self-Serve Account Deletion).

## Local Development

### Prerequisites
- Node.js 22.12.0 (use `nvm use` to switch to the correct version)
- AWS SAM CLI
- Docker (for LocalStack DynamoDB)

### Running Locally

1. Start LocalStack (DynamoDB):
   ```bash
   cd localstack
   docker-compose up -d
   cd ..
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Build the application:
   ```bash
   npm run build
   ```

4. Start the local API:
   ```bash
   npm run start:local
   ```

The API will be available at `http://localhost:3000`.

### Complete Local Testing Workflow

**Terminal 1 - Start LocalStack:**
```bash
cd localstack
docker-compose up
```

**Terminal 2 - Start SAM Local:**
```bash
npm run build
npm run start:local
```

**Terminal 3 - Generate test URL and test:**
```bash
# Generate encrypted JWT
npx tsx scripts/encrypt-message-locally.ts

# Copy the encrypted JWT output, then test:
curl "http://localhost:3000/authorize?request=<PASTE_ENCRYPTED_JWT_HERE>"

# Or open in browser:
# http://localhost:3000/authorize?request=<PASTE_ENCRYPTED_JWT_HERE>
```

**Terminal 4 - Check DynamoDB:**
```bash
# View all authorization codes stored
aws dynamodb scan \
  --table-name local-AMCStub-Authorization \
  --endpoint-url http://localhost:4567 \
  --region eu-west-2 \
  --no-sign-request
```

### Exploring DynamoDB Locally

You can explore the DynamoDB table using the AWS CLI:

```bash
# Scan all items in the authorization table
aws dynamodb scan \
  --table-name local-AMCStub-Authorization \
  --endpoint-url http://localhost:4567 \
  --region eu-west-2 \
  --no-sign-request

### Testing the Authorize GET Flow

1. Generate an encrypted JWT:
   ```bash
   npx tsx scripts/encrypt-message-locally.ts
   ```
   This will output an encrypted JWT token.

2. Test locally by opening in a browser:
   ```
   http://localhost:3000/authorize?request=<ENCRYPTED_JWT>
   ```

3. Test in AWS (dev environment):
   ```
   https://amcstub.signin.dev.account.gov.uk/authorize?request=<ENCRYPTED_JWT>
   ```

You should see an HTML page displaying the decrypted JAR header and payload.

### Running Tests

```bash
npm run test-unit
```