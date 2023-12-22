#!/bin/bash

keys_dir="keys"

mkdir ./${keys_dir}

# ES512
# private key
openssl ecparam -genkey -name secp521r1 -noout -out ./${keys_dir}/ecdsa-p521-private.pem
# public key
openssl ec -in ./${keys_dir}/ecdsa-p521-private.pem -pubout -out ./${keys_dir}/ecdsa-p521-public.pem
