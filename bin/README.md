# bin scripts

This directory contains [`podman`](https://docs.podman.io/en/latest/)-based Shell scripts required when running the DID toolbox as Podman image.

Assuming the `mvn package` has already been executed, to create a Podman image featuring the DID toolbox, if not created already, please run: 
```shell
./bin/podman-build.sh
```

So, running the `podman image ls` command right after should result in at least two entries:
```text
REPOSITORY                            TAG         IMAGE ID      CREATED         SIZE
localhost/e-id-admin/didtoolbox-java  latest      afb7d10ad258  15 minutes ago  607 MB
docker.io/library/openjdk             23          b37c977c525b  3 months ago    598 MB
```

Finally, once you manage to build a Podman image in your local repo, to run the DID toolbox (as Podman image), please use the `didtoolbox.sh` script, e.g.:

```text
$ ./bin/didtoolbox.sh -h

Usage: didtoolbox [options] [command] [command options]
  Options:
    --help, -h    Display help for the DID toolbox
    --version, -V Display version (default: false)
  Commands:
    create      Create a did:tdw DID Document. Optionally sign the initial log entry if a private key is provided
      Usage: create [options]
        Options:
          --assert, -a
            An assertion method (comma-separated) parameters: a key name as well as a JWKS file containing Ed25519 public/verifying key, as defined 
            by DIDs v1.0 (https://www.w3.org/TR/did-core/#assertion)
          --auth, -t
            An authentication method (comma-separated) parameters: a key name as well as a JWKS file containing Ed25519 public/verifying key, as 
            defined by DIDs v1.0 (https://www.w3.org/TR/did-core/#authentication)
        * --domain, -d
            The domain for the DID (e.g. example.com)
          --help, -h
            Display help for the DID toolbox 'create' command
          --jks-alias
            Java KeyStore alias
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the keys from
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore
          --path, -p
            Path segment for the DID (e.g. UUID/GUID)
          --signing-key-file, -s
            The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format
          --verifying-key-file, -v
            The ed25519 public key file for the DID Document’s verification method. In PEM format

$ ./bin/didtoolbox.sh -V

didtoolbox 0.5
```

Probably the simplest way to use the generator would be to let it generate as much on its own as possible:

```shell
./bin/didtoolbox.sh create -d https://domain.com:443
```

The command would create a valid DID log entry also featuring some assertion/verification keys in [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) format.
Beyond that, and since no [verification material](https://www.w3.org/TR/did-core/#verification-material) is supplied explicitly, 
the generator will take care of that, too. Hence, all required key pairs will also be generated and stored in `.didtoolbox` directory, for later use:

```shell
# ll .didtoolbox
total 32
-rw-------@ 1 u80850818  staff   162B Dec 30 13:51 assert-key-01.json
-rw-------@ 1 u80850818  staff   160B Dec 30 13:51 auth-key-01.json
-rw-------  1 u80850818  staff   119B Dec 30 13:51 id_ed25519
-rw-r--r--  1 u80850818  staff   113B Dec 30 13:51 id_ed25519.pub
```

This implies that you may now also try running the command in a usual/recommended way:

```shell
./bin/didtoolbox.sh create \
    -a assert-key-01,.didtoolbox/assert-key-01.json \
    -t auth-key-01,.didtoolbox/auth-key-01.json \
    -d https://domain.com:443 \
    -p path1/path2 \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub                                                      
```

As this repo already contains some keys intended for testing purposes, feel free to also try out the following example: 

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/myjsonwebkeys.json \
    -t my-auth-key-01,src/test/data/myjsonwebkeys.json \
    -d https://domain.com:443 \
    -p path1/path2 \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias    myalias                                              
```

 Alternatively, besides Java KeyStore (PKCS12) also PEM format of signing/verifying key is supported:

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/myjsonwebkeys.json \
    -t my-auth-key-01,src/test/data/myjsonwebkeys.json \
    -d https://domain.com:443 \
    -p path1/path2 \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem                                              
```

So, regardless of whether [verification material](https://www.w3.org/TR/did-core/#verification-material) is generated 
or supplied manually via `-a`/`-t` CLI options, a generated DID log entry will always feature some e.g. the command above 
should produce a following output (_prettified_/_pretty-printed_ version):

```json
[
  "1-QmPYczq8srCY3QjDkgrcwqgur1jq9Rs5o2fKSuozvdgqPw",
  "2024-12-25T13:58:36Z",
  {
    "method": "did:tdw:0.3",
    "scid": "QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X",
    "updateKeys": [
      "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"
    ],
    "prerotation": false,
    "portable": false
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1"
      ],
      "id": "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2",
      "authentication": [
        "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-auth-key-01",
          "controller": "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "my-auth-key-01",
            "x": "6sp4uBi3AHRDEFM1wQIyEzjC_sGYDdnSo01N-s_zDYU"
          }
        },
        {
          "id": "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-assert-key-01",
          "controller": "did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "my-assert-key-01",
            "x": "jcAGpa7VpH8SjTjxqXs1bqq8jUjKYE8IrYrU_XY4zg0"
          }
        }
      ]
    }
  },
  {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2024-12-25T13:58:36Z",
    "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
    "proofPurpose": "authentication",
    "challenge": "1-QmPYczq8srCY3QjDkgrcwqgur1jq9Rs5o2fKSuozvdgqPw",
    "proofValue": "z5L1jUtzJ4T7zjr9TaH9HKYNKkv4LHhmKa8URJeSRqMHRdsTVf4xRDPr9PoBwkFojU67Yh1u4asdbUg8y3Fh9b4ZC"
  }
]
```

The same content _un-prettified_, as it should be found in the `did.jsonl` file:

```json
["1-QmPYczq8srCY3QjDkgrcwqgur1jq9Rs5o2fKSuozvdgqPw","2024-12-25T13:58:36Z",{"method":"did:tdw:0.3","scid":"QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2","authentication":["did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-auth-key-01","controller":"did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-auth-key-01","x":"6sp4uBi3AHRDEFM1wQIyEzjC_sGYDdnSo01N-s_zDYU"}},{"id":"did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2#my-assert-key-01","controller":"did:tdw:QmTKT5fyz9A3rsuSE5iMeC1Z3NXP6in5ZCV5VYVXodYV7X:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"my-assert-key-01","x":"jcAGpa7VpH8SjTjxqXs1bqq8jUjKYE8IrYrU_XY4zg0"}}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2024-12-25T13:58:36Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmPYczq8srCY3QjDkgrcwqgur1jq9Rs5o2fKSuozvdgqPw","proofValue":"z5L1jUtzJ4T7zjr9TaH9HKYNKkv4LHhmKa8URJeSRqMHRdsTVf4xRDPr9PoBwkFojU67Yh1u4asdbUg8y3Fh9b4ZC"}]
```
