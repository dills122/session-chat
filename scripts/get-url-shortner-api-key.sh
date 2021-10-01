#!/bin/bash

API_KEY_OUTPUT=$(docker exec -it session-chat_url-shortner shlink api-key:generate --no-ansi)
echo $API_KEY_OUTPUT
OUTPUT_ARRAY=($API_KEY_OUTPUT)
OUTPUT_STATUS="${OUTPUT_ARRAY[1]}" # First one is an empty string

if [ $OUTPUT_STATUS != "[OK]" ]; then
    exit 0
fi

UNSANITIZED_API_KEY="${OUTPUT_ARRAY[5]}" # Api key with surrounding quoutes

CLEAN_API_KEY=$(sed -e 's/^"//' -e 's/"$//' <<<"$UNSANITIZED_API_KEY")

export URL_SHORTNER_API_KEY=$(echo "$CLEAN_API_KEY" | tr -d '"')
