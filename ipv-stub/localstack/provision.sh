#!/bin/bash

# This script can be run within a docker container running localstack by mounting
# at the localstack bootstrap location /etc/localstack/init/ready.d/init-aws.sh or
# it can be run at the command line where an instance of localstack is running in
# the background.
#
# Anticipated use cases are:
# * local developers running the script by placing it inside a docker container in
#   the location stated above with the file name that localstack looks for when
#   starting up.
# * in a GitHub action step where it will be run directly in a process where localstack
#   is running in the background.

#############################################
# Create environment variables for localstack
#############################################
setup_environment() {
  # Set the endpoint URL for DynamoDB
  ENDPOINT_URL="http://localhost:4566"

  # Set the AWS region
  export REGION="${AWS_DEFAULT_REGION:-eu-west-2}"
}

create_ipv_stub_table() {
  aws --endpoint-url=$ENDPOINT_URL dynamodb create-table \
      --table-name local-AuthIpvStub-UserIdentity \
      --attribute-definitions AttributeName=UserIdentityId,AttributeType=S \
      --key-schema AttributeName=UserIdentityId,KeyType=HASH \
      --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
      --region "$REGION"

  aws --endpoint-url=$ENDPOINT_URL dynamodb put-item \
      --table-name local-AuthIpvStub-UserIdentity  \
      --region "$REGION" \
      --item '
        {
          "UserIdentityId": {
            "S": "test"
          }
        }'

  aws --endpoint-url=$ENDPOINT_URL dynamodb create-table \
      --table-name local-AuthIpvStub-Reverification \
      --attribute-definitions AttributeName=ReverificationId,AttributeType=S \
      --key-schema AttributeName=ReverificationId,KeyType=HASH \
      --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
      --region "$REGION"
}


setup_environment
create_ipv_stub_table
