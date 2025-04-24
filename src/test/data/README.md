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
# CAUTION Different store and key passwords not supported for PKCS12 KeyStores
keytool -importkeystore \
    -deststorepass changeit \
    -destkeypass   changeit \
    -destkeystore  mykeystore.jks \
    -srckeystore   mykeystore.p12 \
    -srcstoretype  PKCS12 \
    -srcstorepass  changeit \
    -alias         myalias
```

By merely repeating the procedure described above, you may keep adding further (PKCS12 keystore) entries into the JKS store.
To list all entries available in the JKS (use -v for verbose output), simply rely on the `keytool -list` command, e.g.:

```shell
keytool -list -storepass changeit -keystore mykeystore.jks
```

which should produce the following output:

```
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 3 entries

myalias, Dec 9, 2024, PrivateKeyEntry, 
Certificate fingerprint (SHA-256): B9:8F:73:F8:EF:C8:E9:B1:7B:63:DF:A6:5C:B5:52:75:FB:B5:05:FF:B6:B2:57:3F:85:03:9A:75:32:90:28:ED
myalias2, Mar 21, 2025, PrivateKeyEntry, 
Certificate fingerprint (SHA-256): 2C:14:57:A0:BB:37:44:97:F9:3C:E6:33:4C:F5:0F:E9:AC:AB:86:01:CC:CE:59:BD:4D:62:42:3E:A9:40:6C:40
myalias3, Mar 21, 2025, PrivateKeyEntry, 
Certificate fingerprint (SHA-256): EB:82:96:8D:B3:68:C5:AE:D9:59:39:46:16:30:3B:CC:7C:06:48:D6:45:BA:72:01:38:12:61:45:B1:93:F6:00
```

:warning: **DISCLAIMER The entire key material stored in this directory is exclusively intended FOR TESTING PURPOSES and should NOT be therefore used for any other purposes.**
