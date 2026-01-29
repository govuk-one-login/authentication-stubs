#!/bin/bash

#############################################
# Create environment variables for localstack
#############################################
setup_environment() {
  ENDPOINT_URL="http://localhost:4566"
  export REGION="${AWS_DEFAULT_REGION:-eu-west-2}"
}

create_amc_stub_table() {
  aws --endpoint-url=$ENDPOINT_URL dynamodb create-table \
      --table-name local-AMCStub-Authorization \
      --attribute-definitions AttributeName=AuthorizationId,AttributeType=S \
      --key-schema AttributeName=AuthorizationId,KeyType=HASH \
      --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
      --region "$REGION"
}

setup_environment
create_amc_stub_table
