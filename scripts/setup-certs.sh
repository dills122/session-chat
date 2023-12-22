#!/bin/bash
DOMAINDEFAULT="dsteele.dev"
site_name="${1:-$DOMAINDEFAULT}"
cert_dir="certs"

mkdir ./${cert_dir}

# TODO add check for system type or arg for system
sh ./configure-hosts-unix.sh $site_name

which -s brew
if [[ $? != 0 ]]; then
    # Install Homebrew
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    brew update
fi

brew install mkcert
brew install nss

# Initialize and create certificates
mkcert -install
# mkdir -p certs
mkcert -key-file ./${cert_dir}/ssl.key -cert-file ./${cert_dir}/ssl.crt *.${site_name}
