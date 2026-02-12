#!/usr/bin/env bash
set -euo pipefail

ENVIRONMENTS=("authdev1" "authdev2" "authdev3" "dev")
REGION="eu-west-2"
PROFILE="di-authentication-development-AdministratorAccessPermission"

echo "Fetching AMC signing public keys from auth account and storing for stub..."
echo ""

for env in "${ENVIRONMENTS[@]}"; do
    echo "=== $env ==="

    # Fetch auth-to-amc signing key (for AMC audience)
    AMC_KEY_ALIAS="alias/${env}-auth-to-amc-signing-key"
    AMC_KEY_ID=$(aws kms describe-key \
        --key-id "$AMC_KEY_ALIAS" \
        --region "$REGION" \
        --profile "$PROFILE" \
        --query 'KeyMetadata.KeyId' \
        --output text 2>/dev/null || echo "NOT_FOUND")

    if [ "$AMC_KEY_ID" != "NOT_FOUND" ]; then
        AMC_PUBLIC_KEY=$(aws kms get-public-key \
            --key-id "$AMC_KEY_ID" \
            --region "$REGION" \
            --profile "$PROFILE" \
            --query 'PublicKey' \
            --output text | base64 -d | openssl ec -pubin -pubout 2>/dev/null)

        aws secretsmanager put-secret-value \
            --secret-id "/${env}/stubs/amc-stub-public-key-amc-audience" \
            --secret-string "$AMC_PUBLIC_KEY" \
            --region "$REGION" \
            --profile "$PROFILE" 2>/dev/null || \
        aws secretsmanager create-secret \
            --name "/${env}/stubs/amc-stub-public-key-amc-audience" \
            --secret-string "$AMC_PUBLIC_KEY" \
            --region "$REGION" \
            --profile "$PROFILE"

        echo "✓ Stored AMC audience signing key"
    else
        echo "⚠ AMC signing key not found: $AMC_KEY_ALIAS"
    fi

    # Fetch auth-to-account-management signing key (for Auth audience)
    AUTH_KEY_ALIAS="alias/${env}-auth-to-account-management-signing-key"
    AUTH_KEY_ID=$(aws kms describe-key \
        --key-id "$AUTH_KEY_ALIAS" \
        --region "$REGION" \
        --profile "$PROFILE" \
        --query 'KeyMetadata.KeyId' \
        --output text 2>/dev/null || echo "NOT_FOUND")

    if [ "$AUTH_KEY_ID" != "NOT_FOUND" ]; then
        AUTH_PUBLIC_KEY=$(aws kms get-public-key \
            --key-id "$AUTH_KEY_ID" \
            --region "$REGION" \
            --profile "$PROFILE" \
            --query 'PublicKey' \
            --output text | base64 -d | openssl ec -pubin -pubout 2>/dev/null)

        aws secretsmanager put-secret-value \
            --secret-id "/${env}/stubs/amc-stub-public-key-auth-audience" \
            --secret-string "$AUTH_PUBLIC_KEY" \
            --region "$REGION" \
            --profile "$PROFILE" 2>/dev/null || \
        aws secretsmanager create-secret \
            --name "/${env}/stubs/amc-stub-public-key-auth-audience" \
            --secret-string "$AUTH_PUBLIC_KEY" \
            --region "$REGION" \
            --profile "$PROFILE"
        
        echo "✓ Stored Auth audience signing key"
    else
        echo "⚠ Auth signing key not found: $AUTH_KEY_ALIAS"
    fi
    
    echo ""
done

echo "Done!"
