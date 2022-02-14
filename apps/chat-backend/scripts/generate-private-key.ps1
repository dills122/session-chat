# ES512
# private key
openssl ecparam -genkey -name secp521r1 -noout -out ./keys/ecdsa-p521-private.pem
# public key
openssl ec -in ./keys/ecdsa-p521-private.pem -pubout -out ./keys/ecdsa-p521-public.pem 