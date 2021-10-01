#!/bin/bash

# loads all of the vars in the .env file in base dir
export $(grep -v '^#' .env | xargs)

# starts the url shortner service
docker run -d \
    --name session-chat_url-shortner \
    -p 8080:8080 \
    -e SHORT_DOMAIN_HOST=$SHORT_DOMAIN_HOST \
    -e SHORT_DOMAIN_SCHEMA=$SHORT_DOMAIN_SCHEMA \
    -e GEOLITE_LICENSE_KEY=$GEOLITE_LICENSE_KEY \
    shlinkio/shlink:stable

sleep 10s

# script used to create and extract api access key from url shortner service
source ./scripts/get-url-shortner-api-key.sh

echo "ENV Var: $URL_SHORTNER_API_KEY"

# starts the remaining docker services
docker compose up -d
