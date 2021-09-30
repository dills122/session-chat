# Session Chat: Secure Session Chatrooms

[![CI Job](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml)

Chat securely with one or more associates without a worry of it getting out.

## Getting Started

```bash
# installs all dependencies
rush install
```

```bash
# Sets up the SSL certs for local development
./scripts/setup-certs-windows.ps1
```

```bash
cd ./app/chat-backend/
# generate the keys for JWT tokens
mkdir ./keys && cd ./keys
../generate-private-key.ps1 # or .sh
```

```bash
# starts dev env
rush docker-up:dev
# start UI project separately
cd ./apps/chat-frontend/ && rushx start:dev
```
