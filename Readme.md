# Session Chat: Secure Session Chatrooms

[![CI Job](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml/badge.svg)](https://github.com/dills122/session-chat/actions/workflows/ci.action.yml)

Chat securely with one or more associates without a worry of it getting out.

## Getting Started

Use Node.js `20.x` for local development. The repo also runs cleanly on newer Node releases, but `20.x` is the current baseline used in CI.

```bash
# setup the correct node version
nvm install 20
nvm use 20
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

## Docs

- [Docs Overview](./docs/README.md)
- [Dependency Upgrade Plan](./docs/dependency-upgrade-plan.md)

### Frontend

The frontend lives in `apps/chat-frontend` and currently uses Angular 20, Nebular, and Tailwind utilities.

```bash
cd apps/chat-frontend
rushx start:dev
```

## Notes & Misc

### Upgrading Packages

```bash
# check all packages but angular ones
ncu '/^(?!.*angular).*$/'
```
