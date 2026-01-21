# AMC Stub

Authentication stub for AMC (Account Management Components) services. This stub will provide functionality for the
OAuth part of Authentication interactions with AMC, as well as provide functionality to interact with the Authentication
Account Management API for the SSAD flow (Self-Serve Account Deletion).

## Local Development

### Prerequisites
- Node.js 22.12.0 (use `nvm use` to switch to the correct version)
- AWS SAM CLI

### Running Locally

1. Install dependencies:
   ```bash
   npm install
   ```

2. Build the application:
   ```bash
   npm run build
   ```

3. Start the local API:
   ```bash
   npm run start:local
   ```

The API will be available at `http://localhost:3000`.

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