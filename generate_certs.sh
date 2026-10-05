#!/bin/bash
mkdir -p certs && cd certs

# 1. Root CA
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=DCSM-RootCA"

# 2. Server Certificate (Valid)
openssl req -newkey rsa:2048 -nodes \
  -keyout server.key -out server.csr -subj "/CN=storage-server"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365

# 3. Client Certificate (Valid)
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr -subj "/CN=valid-client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# 4. Untrusted Client Certificate (Untuk TC-RPL-03)
openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
  -keyout bad_client.key -out bad_client.crt -subj "/CN=untrusted-client"

echo "Sertifikat mTLS berhasil dibuat."
