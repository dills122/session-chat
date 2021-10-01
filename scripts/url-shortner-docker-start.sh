#!/bin/bash

export $(grep -v '^#' .env | xargs)

docker run -d \
    --name session-chat_url-shortner \
    -p 8080:8080 \
    -e SHORT_DOMAIN_HOST=$SHORT_DOMAIN_HOST \
    -e SHORT_DOMAIN_SCHEMA=$SHORT_DOMAIN_SCHEMA \
    -e GEOLITE_LICENSE_KEY=$GEOLITE_LICENSE_KEY \
    shlinkio/shlink:stable

sh ./scripts/get-url-shortner-api-key.sh

docker compose up -d
