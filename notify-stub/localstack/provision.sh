#!/bin/bash

echo "Creating DynamoDB table for Notify stub..."

awslocal dynamodb create-table \
	--table-name NotificationsTable \
	--attribute-definitions \
	AttributeName=destination,AttributeType=S \
	AttributeName=notification_id,AttributeType=S \
	--key-schema \
	AttributeName=destination,KeyType=HASH \
	AttributeName=notification_id,KeyType=RANGE \
	--billing-mode PAY_PER_REQUEST \
	--region eu-west-2

echo "DynamoDB table created successfully"
