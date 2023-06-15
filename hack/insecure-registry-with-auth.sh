#!/bin/bash

set -euo pipefail

export REGISTRY_USER=ci-user
export REGISTRY_PASSWORD="$(openssl rand -base64 16)"

mkdir -p ca certs

# Create a certificate authority
openssl rand -base64 48 > passphrase.txt

openssl genrsa \
	-des3 \
	-out ca.key \
	--passout file:passphrase.txt 2048

openssl req \
	-x509 \
	-new \
	-nodes \
	-key ca.key \
	--passin file:passphrase.txt \
	-sha256 \
	-days 1825 \
	-out ca.pem \
	-subj "/C=US/CN=faux-ca"

# Create a certificate signing request for localhost
openssl req \
	-nodes \
	-newkey rsa:2048 \
	-keyout certs/domain.key \
	-out certs/domain.csr \
	-subj "/C=US/CN=coco-tests"

cat <<EOF > domains.ext
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Sign the certificate using the CA cert
openssl x509 -req \
	-in certs/domain.csr \
	-CA ./ca.pem \
	-CAkey ./ca.key \
	--passin file:passphrase.txt \
	-CAcreateserial \
	-days 1 \
	-sha256 \
	-extfile domains.ext \
	-out certs/domain.crt

# Create a htpasswd file
mkdir -p auth
 docker run \
  --entrypoint htpasswd \
  httpd:2 -Bbn "$REGISTRY_USER" "$REGISTRY_PASSWORD" > auth/htpasswd

# Start the registry with TLS and basic auth
docker run -d \
  -p 5000:5000 \
  --restart=always \
  --name registry \
  -v "$(pwd)"/auth:/auth \
  -e "REGISTRY_AUTH=htpasswd" \
  -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" \
  -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd \
  -v "$(pwd)"/certs:/certs \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
  -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
  registry:2

docker login -u "$REGISTRY_USER" -p "$REGISTRY_PASSWORD" localhost:5000

docker pull busybox
docker tag busybox localhost:5000/local/busybox
docker push localhost:5000/local/busybox

docker rm -f registry
