#!/bin/bash

CERT_DIR="./certchain"
mkdir -p "$CERT_DIR"

DAYS=365
KEY_SIZE=2048

echo "Generating Root Certificate..."
openssl genrsa -out "$CERT_DIR/rootCA.key" $KEY_SIZE
openssl req -x509 -new -nodes -key "$CERT_DIR/rootCA.key" -sha256 -days $DAYS -out "$CERT_DIR/rootCA.pem" -subj "/C=US/ST=California/L=San Francisco/O=MyOrg/OU=Root/CN=RootCA"

echo "Generating Intermediate Certificate..."
openssl genrsa -out "$CERT_DIR/intermediateCA.key" $KEY_SIZE
openssl req -new -key "$CERT_DIR/intermediateCA.key" -out "$CERT_DIR/intermediateCA.csr" -subj "/C=US/ST=California/L=San Francisco/O=MyOrg/OU=Intermediate/CN=IntermediateCA"
openssl x509 -req -in "$CERT_DIR/intermediateCA.csr" -CA "$CERT_DIR/rootCA.pem" -CAkey "$CERT_DIR/rootCA.key" -CAcreateserial -out "$CERT_DIR/intermediateCA.pem" -days $DAYS -sha256 -extfile <(echo "basicConstraints=CA:TRUE")

echo "Generating Leaf Certificate..."
openssl genrsa -out "$CERT_DIR/leaf.key" $KEY_SIZE
openssl req -new -key "$CERT_DIR/leaf.key" -out "$CERT_DIR/leaf.csr" -subj "/C=US/ST=California/L=San Francisco/O=MyOrg/OU=Leaf/CN=LeafCertificate"
openssl x509 -req -in "$CERT_DIR/leaf.csr" -CA "$CERT_DIR/intermediateCA.pem" -CAkey "$CERT_DIR/intermediateCA.key" -CAcreateserial -out "$CERT_DIR/leaf.pem" -days $DAYS -sha256 -extfile <(echo "basicConstraints=CA:FALSE")

echo "Encoding certificates to Base64..."

echo "Root Certificate (Base64):"
cat "$CERT_DIR/rootCA.pem" | base64 | tr -d '\n'
echo -e "\n"

echo "Intermediate Certificate (Base64):"
cat "$CERT_DIR/intermediateCA.pem" | base64 | tr -d '\n'
echo -e "\n"

echo "Leaf Certificate (Base64):"
cat "$CERT_DIR/leaf.pem" | base64 | tr -d '\n'
echo -e "\n"

rm "$CERT_DIR"/*.csr
rm "$CERT_DIR"/*.srl
