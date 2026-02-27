#!/bin/bash

echo "Creating DynamoDB table for Notify stub..."

awslocal dynamodb create-table \
	--table-name local-NotifyStub-Notifications \
	--attribute-definitions \
	AttributeName=Destination,AttributeType=S \
	AttributeName=NotificationID,AttributeType=S \
	--key-schema \
	AttributeName=Destination,KeyType=HASH \
	AttributeName=NotificationID,KeyType=RANGE \
	--billing-mode PAY_PER_REQUEST \
	--region eu-west-2

echo "DynamoDB table created successfully"
