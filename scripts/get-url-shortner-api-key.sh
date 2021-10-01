#!/bin/bash
# creates api key inside container pipe to var
API_KEY_OUTPUT=$(docker exec -it session-chat_url-shortner shlink api-key:generate --no-ansi)
OUTPUT_ARRAY=($API_KEY_OUTPUT)
OUTPUT_STATUS="${OUTPUT_ARRAY[1]}" # First one is an empty string
# checks the status of the api key return
if [ $OUTPUT_STATUS != "[OK]" ]; then
    exit 0
fi

UNSANITIZED_API_KEY="${OUTPUT_ARRAY[5]}" # Api key with surrounding quoutes
# removes the surrounding " from the api key
CLEAN_API_KEY=$(sed -e 's/^"//' -e 's/"$//' <<<"$UNSANITIZED_API_KEY")
# adds the new key to env variables
export URL_SHORTNER_API_KEY="$CLEAN_API_KEY"
