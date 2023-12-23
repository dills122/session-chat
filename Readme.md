# Session Chat: Secure Session Chatrooms

[![CI Job](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml)

Chat securely with one or more associates without a worry of it getting out.

## Getting Started

```bash
# installs all dependencies
rush install
```

### Setting Up Local Env

Ensure you have `mkcert` installed on your PC, below will be the instructions for windows.

Open a new `powershell` in `administrator` mode and run `choco install mkcert`.

```bash
# Sets up the SSL certs for local development
./scripts/setup-certs-windows.ps1
```

Now you'll need to setup the keys used by the backend for the `JWT` tokens

```bash
# If first setup, create the keys dir
mkdir ./apps/chat-backend/keys/
./scripts/setup-backend-keys.ps1
```

Now that all the dependencies are setup you can spin up the local docker env.

```bash
# starts dev env
rush docker-up:dev
# start UI project separately
cd ./apps/chat-frontend/ && rushx start:dev
```

### Upgrading Packages

```bash
# check all packages but angular ones
ncu '/^(?!.*angular).*$/'
```
