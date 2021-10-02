#!/bin/bash

docker stop session-chat_url-shortner

docker rm session-chat_url-shortner

docker compose down
