# Session Chat: Secure Session Chatrooms

[![CI Job](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml)

Chat securely with one or more associates without a worry of it getting out.

## Session Chat 2.0 design exploration

The repository is planning a security and product redesign around temporary,
end-to-end encrypted sessions with pluggable admission and delivery profiles.
The proposal, threat model, research backlog, and architecture decisions are
indexed in [the v2 design documents](docs/README.md).

The Angular, NestJS, Socket.IO, JWT, and Redis application described below is
the legacy prototype. It does not yet implement the v2 security architecture.

## Getting Started

At the moment this will need `node v18` or greater.

```bash
# setup the correct node version
nvm install lts/hydrogen
nvm use lts/hydrogen
# installs all dependencies
rush install
# sanity check
rush test:ci
```

### Setting Up Local Env

If your on MacOS then you can get away with just running the `./scripts/setup-certs.sh`.

For other OS's you'll need to make sure these dependencies are installed first.

Install `mkcert` & `nss` through `choco` for `Windows` or `apt-get` on your linux distro.

**Note `powershell` needs to be run in `administrator` mode.**

MacOS Setup:

```bash
# Sets up the SSL certs for local development
./scripts/setup-certs.sh
# Adds needed rows to the hosts file
./scripts/configure-hosts-unix.sh
# Setup Encryption keys for backend
./scripts/setup-backend-keys.sh
```

Now that all the dependencies are setup you can spin up the local docker env.

```bash
# starts dev env
rush docker-up:dev
# start UI project separately
cd ./apps/chat-frontend/ && rushx start:dev
```

## Notes & Misc

### Upgrading Packages

```bash
# check all packages but angular ones
ncu '/^(?!.*angular).*$/'
```
