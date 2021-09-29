#!/bin/bash

API_KEY_OUTPUT=$(docker exec -it session-chat_url-shortner_1 shlink api-key:generate --no-ansi)
OUTPUT_ARRAY=($API_KEY_OUTPUT)
OUTPUT_STATUS="${OUTPUT_ARRAY[0]}"

if [ $OUTPUT_STATUS != "[OK]"]; then
    exit 0
fi

IFS=':'
OUTPUT_SPLIT=($API_KEY_OUTPUT)
unset IFS

API_KEY=$(echo "$OUTPUT_SPLIT" | tr -d '"')

docker exec -it session-chat_chat-backend_1 URL_API_KEY="$API_KEY"
