# IPV stub

## Running Locally

```bash
(cd localstack && docker compose up)
```
```bash
npm run build && npm run start:local
```

You can hit the /authorize endpoint on the locally running stub with a valid request param.

To construct an appropriately encrypted request param for use locally, you can use the helper script (/scripts/encrypt-message-locally.mjs).
Manually adjust the algorithm, payload and data to be base 64 encoded and encrypted directly in the script, and run it via

```bash
npm run encryptSampleRequest
```

Then use the output to construct a request e.g. `http://localhost:3000/authorize?request=[your-encrypted-jwe]`

## Private and public keys

Private and public keys are be needed for decryption and signature validation.

The local private key (in _parameters.json_) as well as its public key (in the encrypt helper script) have been commited deliberately. 
The key pair was generated fresh and should only be used for testing, both locally and as part of the pre-merge GitHub workflow.

In deployed environments, the private key will be retrieved from AWS Secrets Manager, and the public key from AWS Parameter Store. This key pair is different from the one which has been commited here.


## Connect to DynamoDB with IntelliJ Database Explorer

1) Create a `localstack` AWS profile

```
> aws configure --profile localstack
AWS Access Key ID [None]: na
AWS Secret Access Key [None]: na
Default region name [None]: eu-west-2
```

2) Navigate File > New > Datasource > DynamoDB
3) Submit with:
    - Host: `localhost`
    - Port: `4566`
    - Region: `eu-west-2`
    - Authentication: `AWS Profile`
    - Profile: `localstack`
4) Navigate View > Tool Windows > Database