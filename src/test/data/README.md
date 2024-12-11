# Test data

Here is a short procedure on how to store a Ed25519 private key into the Java KeyStore (JKS) of type PKCS12, suitable for testing purposes.

Nothing but a few conventional CLI tool are required: `openssl` and `keytool`.

```shell
# Create a ED25519 private key
openssl genpkey -algorithm ed25519 -out private.pem
#openssl pkey -in private.pem -pubout -out public.pem
#openssl pkey -inform pem -in private.pem -outform der -out private.der
#cat private.pem | openssl pkey -pubout -outform der -out public.der

# Generate cert request for CA
openssl req -x509 -sha256 -new -key private.pem -out myserver.csr

# Generate self signed expiry-time 10 years
openssl x509 -sha256 -days 3652 -in myserver.csr -signkey private.pem -out myselfsigned.crt

# Create PKCS12 keystore from private key and public certificate
openssl pkcs12 -export -name myalias -in myselfsigned.crt -inkey private.pem -out mykeystore.p12

# Convert PKCS12 keystore into a JKS keystore
keytool -importkeystore \
    -deststorepass changeit \
    -destkeypass   changeit \
    -destkeystore  mykeystore.jks \
    -srckeystore   mykeystore.p12 \
    -srcstoretype  PKCS12 \
    -srcstorepass  changeit \
    -alias         myalias

# To verify the contents of the JKS
keytool -list -v -storepass changeit -keystore mykeystore.jks
```

:warning: **DISCLAIMER All the keys stored in this directory are exclusively intended FOR TESTING PURPOSES and should NOT be used for any other purposes.**
