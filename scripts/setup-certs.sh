#!/bin/bash
DOMAINDEFAULT="dsteele.dev"
site_name="${1:-$DOMAINDEFAULT}"
cert_dir="certs"

echo "Making cert dir if not already existing"
mkdir ./${cert_dir}

echo "Configuring local hosts"
# TODO add check for system type or arg for system
sh ./scripts/configure-hosts-unix.sh $site_name

if [ "$(uname)" == "Darwin" ]; then
  echo "Setting up Brew"
  sh ./scripts/brew-setup.sh
# elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
#   # Do something under GNU/Linux platform
# elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
#   # Do something under 64 bits Windows NT platform
fi

# Initialize and create certificates
mkcert -install
# mkdir -p certs
mkcert -key-file ./${cert_dir}/ssl.key -cert-file ./${cert_dir}/ssl.crt *.${site_name}
