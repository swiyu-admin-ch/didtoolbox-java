# bin scripts

This directory contains [`podman`](https://docs.podman.io/en/latest/)-based Shell scripts required when running the DID toolbox as Podman image.

Assuming the `mvn package` has already been executed, to create a Podman image featuring the DID toolbox, if not created already, please run: 
```shell
./bin/podman-build.sh
```

So, running the `podman image ls` command right after should result in at least two entries:
```text
REPOSITORY                                TAG                IMAGE ID      CREATED         SIZE
localhost/swiyu-admin-ch/didtoolbox-java  latest             3cd22c82b319  17 minutes ago  540 MB
docker.io/library/openjdk                 26-slim            5e18f6a9a13d  6 days ago      510 MB
```

Finally, once you manage to build a Podman image in your local repo, to run the DID toolbox (as Podman image), please use the `didtoolbox.sh` script, e.g.:

```text
$ ./bin/didtoolbox.sh -h

[the entire help page should be displayed here]

$ ./bin/didtoolbox.sh -V

didtoolbox 1.4.0
```

Probably the simplest way to use the generator would be to let it generate as much on its own as possible:

```shell
./bin/didtoolbox.sh create -u https://domain.com/path1/path2/did.jsonl
```

The command would create a valid DID log entry also featuring some assertion/verification keys in various format such as [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) and PEM.
Beyond that, and since no [verification material](https://www.w3.org/TR/did-core/#verification-material) is supplied explicitly, 
the generator will take care of that, too. Hence, all required key pairs will also be generated and stored in `.didtoolbox` directory, for later use:

```shell
# ll .didtoolbox
total 64
-rw-------@ 1 u80850818  staff   154B Jan 15 15:14 assert-key-01
-rw-------@ 1 u80850818  staff   209B Jan 15 15:14 assert-key-01.json
-rw-r--r--@ 1 u80850818  staff   178B Jan 15 15:14 assert-key-01.pub
-rw-------@ 1 u80850818  staff   154B Jan 15 15:14 auth-key-01
-rw-------@ 1 u80850818  staff   207B Jan 15 15:14 auth-key-01.json
-rw-r--r--@ 1 u80850818  staff   178B Jan 15 15:14 auth-key-01.pub
-rw-------@ 1 u80850818  staff   119B Jan 15 13:29 id_ed25519
-rw-r--r--@ 1 u80850818  staff   113B Jan 15 13:29 id_ed25519.pub
```

This implies that you may now also try running the command in a usual/recommended way:

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,.didtoolbox/assert-key-01.pub \
    -t my-auth-key-01,.didtoolbox/auth-key-01.pub \
    -u https://domain.com/path1/path2/did.jsonl \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub                                                      
```

As this repo already contains some keys intended for testing purposes, feel free to also try out the following example: 

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com/path1/path2/did.jsonl \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias    myalias                                              
```

 Alternatively, besides Java KeyStore (PKCS12) also PEM format of signing/verifying key is supported:

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com/path1/path2/did.jsonl \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem
```

So, regardless of whether [verification material](https://www.w3.org/TR/did-core/#verification-material) is generated 
or supplied manually via `-a`/`-t` CLI options, a generated DID log entry will always feature some e.g. the command above 
should produce a following output (_prettified_/_pretty-printed_ version):

```json
[
  "1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK",
  "2025-06-04T21:06:36Z",
  {
    "method": "did:tdw:0.3",
    "scid": "QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn",
    "updateKeys": [
      "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"
    ],
    "portable": false
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/jwk/v1"
      ],
      "id": "did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2",
      "authentication": [
        "did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "my-auth-key-01",
            "x": "-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg",
            "y": "Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"
          }
        },
        {
          "id": "did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "my-assert-key-01",
            "x": "wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y",
            "y": "eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-06-04T21:06:36Z",
      "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
      "proofPurpose": "authentication",
      "challenge": "1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK",
      "proofValue": "z2j8SuRZUw1LLaXsW8D7oBtckovZoaMxH5VhD8gmSjHUyZuauWZvA2uvm5whWvZXoLTnQjsRxdN9qN1K9BZd6vqrR"
    }
  ]
]
```

The same content _un-prettified_, as it should be found in the `did.jsonl` file:

```json
["1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK","2025-06-04T21:06:36Z",{"method":"did:tdw:0.3","scid":"QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2","authentication":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-06-04T21:06:36Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK","proofValue":"z2j8SuRZUw1LLaXsW8D7oBtckovZoaMxH5VhD8gmSjHUyZuauWZvA2uvm5whWvZXoLTnQjsRxdN9qN1K9BZd6vqrR"}]]
```

Once a newly created `did.jsonl` file is available, you may use the `update` subcommand at any point to **completely**
replace the existing [verification material](https://www.w3.org/TR/did-core/#verification-material) in DID document:

```shell
./bin/didtoolbox.sh update \
    -d did.jsonl \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem
```

The command above should produce the following DID log featuring a whole new DID log entry:

```json lines
["1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK","2025-06-04T21:06:36Z",{"method":"did:tdw:0.3","scid":"QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2","authentication":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-06-04T21:06:36Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmTZGzit7hSYSXVmuZy8QFaPStCJQG15wWn53SgyXxCSzK","proofValue":"z2j8SuRZUw1LLaXsW8D7oBtckovZoaMxH5VhD8gmSjHUyZuauWZvA2uvm5whWvZXoLTnQjsRxdN9qN1K9BZd6vqrR"}]]
["2-QmdKRknBB6t68f35MZccFvMWzAArWNWUz44XhcGgeHJ5xg","2025-06-16T14:58:31Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2","authentication":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:QmR7TbG5KdECpqKv6uJPJ9z7p4ey7nVYMjdsoQL6aBpKSn:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-06-16T14:58:31Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"2-QmdKRknBB6t68f35MZccFvMWzAArWNWUz44XhcGgeHJ5xg","proofValue":"z5r1JC6PuD1ErAKjgCTCaBtauAmdepVB8NbPSWxop1fWNoQpZHUmkELrQR2dFN71Hzsh7U1dLEQ5UpmRfvPG9VVkW"}]]
```
