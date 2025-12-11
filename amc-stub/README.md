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
   sam build
   ```

3. Start the local API:
   ```bash
   sam local start-api -p 3001
   ```

4. Test the endpoints:
   ```bash
   # Test GET
   curl http://localhost:3001/authorize
   
   # Test POST
   curl -X POST http://localhost:3001/authorize
   
   # Test unsupported method (should return 405)
   curl -X PUT http://localhost:3001/authorize
   ```

The API will be available at `http://localhost:3001`.

### Running Tests

```bash
npm run test-unit
```