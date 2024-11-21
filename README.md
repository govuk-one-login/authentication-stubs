# di-authentication-stubs

## Test

Run localstack and execute localstack/provision.sh when starting to create resources.

```bash
docker compose up
```

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