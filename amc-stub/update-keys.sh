#!/bin/bash
set -e

ENVIRONMENTS=("build")

for ENV in "${ENVIRONMENTS[@]}"; do
  echo "Generating and uploading keys for $ENV..."
  
  PRIVATE_KEY=$(openssl genrsa 2048 2>/dev/null)
  PUBLIC_KEY=$(echo "$PRIVATE_KEY" | openssl rsa -pubout 2>/dev/null)
  
  # Update or create AMC stub private key
  aws secretsmanager put-secret-value \
    --secret-id "/${ENV}/stubs/amc-stub-private-key" \
    --secret-string "$PRIVATE_KEY" \
    --region eu-west-2 2>/dev/null || \
  aws secretsmanager create-secret \
    --name "/${ENV}/stubs/amc-stub-private-key" \
    --secret-string "$PRIVATE_KEY" \
    --region eu-west-2
  
  # Update or create Auth to AMC public key
  aws secretsmanager put-secret-value \
    --secret-id "/deploy/${ENV}/auth_to_amc_public_encryption_key" \
    --secret-string "$PUBLIC_KEY" \
    --region eu-west-2 2>/dev/null || \
  aws secretsmanager create-secret \
    --name "/deploy/${ENV}/auth_to_amc_public_encryption_key" \
    --secret-string "$PUBLIC_KEY" \
    --region eu-west-2
  
  echo "✓ Updated $ENV"
done

echo "All environments updated successfully"
