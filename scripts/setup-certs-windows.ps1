# Install mkcert, assumes brew already installed
choco install mkcert

# Initialize and create certificates
mkcert -install
mkdir -p certs
mkcert -key-file ../certs/ssl.key -cert-file ../certs/ssl.crt *.dsteele.dev
