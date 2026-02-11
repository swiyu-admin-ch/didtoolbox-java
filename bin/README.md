# bin scripts

This directory contains [`podman`](https://docs.podman.io/en/latest/)-based Shell scripts required when running the DID toolbox as Podman image.

Assuming the `mvn package` has already been executed, to create a Podman image featuring the DID toolbox, if not created already, please run: 
```shell
./bin/podman-build.sh
```

So, running the `podman image ls` command right after should result in at least two entries:
```text
REPOSITORY                                TAG                   IMAGE ID      CREATED        SIZE
localhost/swiyu-admin-ch/didtoolbox-java  latest                ac0e22cd6037  9 minutes ago  433 MB
docker.io/library/eclipse-temurin         25-jre-ubi10-minimal  df9bb383d79d  5 days ago     400 MB
```

Finally, once you manage to build a Podman image in your local repo, to run the DID toolbox (as Podman image), please use the `didtoolbox.sh` script, e.g.:

```text
$ ./bin/didtoolbox.sh -h

[the entire help page should be displayed here]

$ ./bin/didtoolbox.sh -V

[the actual version should be displayed here]
```

Probably the simplest way to use the generator would be to let it generate as much on its own as possible:

```shell
./bin/didtoolbox.sh create -u https://domain.com/path1/path2/did.jsonl -f
```

The command would create a valid DID log entry also featuring some assertion/verification keys in various format such as [JWKS](https://datatracker.ietf.org/doc/html/rfc7517) and PEM.
Beyond that, and since no [verification material](https://www.w3.org/TR/did-core/#verification-material) is supplied explicitly, 
the generator will take care of that, too. Hence, all required key pairs will also be generated and stored in `.didtoolbox` directory, for later use:

```shell
# ll .didtoolbox
total 48
-rw-------  1 vladica.stojic  staff   227B Feb 11 13:53 assert-key-01
-rw-r--r--  1 vladica.stojic  staff   178B Feb 11 13:53 assert-key-01.pub
-rw-------  1 vladica.stojic  staff   227B Feb 11 13:53 auth-key-01
-rw-r--r--  1 vladica.stojic  staff   178B Feb 11 13:53 auth-key-01.pub
-rw-------  1 vladica.stojic  staff   168B Feb 11 13:53 id_ed25519
-rw-r--r--  1 vladica.stojic  staff   113B Feb 11 13:53 id_ed25519.pub
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
{
  "versionId": "1-QmVNnbsLiQ9FR3xLDeDTucTwg9ZwXrF6jvE2jHFA88x1jY",
  "versionTime": "2026-02-11T13:02:04Z",
  "parameters": {
    "method": "did:webvh:1.0",
    "scid": "QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD",
    "updateKeys": [
      "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"
    ],
    "portable": false
  },
  "state": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1"
    ],
    "id": "did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2",
    "authentication": [
      "did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01"
    ],
    "assertionMethod": [
      "did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01"
    ],
    "verificationMethod": [
      {
        "id": "did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01",
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
        "id": "did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01",
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
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2026-02-11T13:02:04Z",
      "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
      "proofPurpose": "assertionMethod",
      "proofValue": "z4z8eeSqiGp9MG2MWwwFqNs3GN5m2XbMPxedYWd3s9yXopnM6oAgAVPS8dMyijDnaMik1Ym7gnD2CWd2mTx685dEV"
    }
  ]
}
```

The same content _un-prettified_, as it should be found in the `did.jsonl` file:

```json
{"versionId":"1-QmVNnbsLiQ9FR3xLDeDTucTwg9ZwXrF6jvE2jHFA88x1jY","versionTime":"2026-02-11T13:02:04Z","parameters":{"method":"did:webvh:1.0","scid":"QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2","authentication":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-02-11T13:02:04Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z4z8eeSqiGp9MG2MWwwFqNs3GN5m2XbMPxedYWd3s9yXopnM6oAgAVPS8dMyijDnaMik1Ym7gnD2CWd2mTx685dEV"}]}
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
{"versionId":"1-QmVNnbsLiQ9FR3xLDeDTucTwg9ZwXrF6jvE2jHFA88x1jY","versionTime":"2026-02-11T13:02:04Z","parameters":{"method":"did:webvh:1.0","scid":"QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2","authentication":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-02-11T13:02:04Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z4z8eeSqiGp9MG2MWwwFqNs3GN5m2XbMPxedYWd3s9yXopnM6oAgAVPS8dMyijDnaMik1Ym7gnD2CWd2mTx685dEV"}]}
{"versionId":"2-QmUznSmYWCL1qE1c6tvkkQUsoV6drWcYC9yLc2V3fAGLiZ","versionTime":"2026-02-11T13:02:49Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2","authentication":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01"],"assertionMethod":["did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:webvh:QmXKFnvqd29GfKgvoGDP7RRyLhiQVWJagFDu6qYghqWBdD:domain.com:path1:path2#my-assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-02-11T13:02:49Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"assertionMethod","proofValue":"z3hoSFSc3PmtApvFti3GaJ3Yg8f5rxHHtdEyEtqCd3CEL87mBtioo2a94NzQXwtXbrMf2wyRHMfTesugJ41txzKpg"}]}
```

To be able to use HSM keys, the relevant [Securosys Primus libraries](https://docs.securosys.com/jce/Downloads/) are required.
For the purpose of referencing them on the file system, the `DIDTOOLBOX_BOOTCLASSPATH` envvar is available e.g.

```shell
# Set the correct envvar value before running the script
DIDTOOLBOX_BOOTCLASSPATH=$(pwd)/securosys/lib \
./bin/didtoolbox.sh create \
    -u https://asd.asd \
    -p src/test/data/com.securosys.primus.jce.credentials.properties \
    -q primus \
    --primus-keystore-password pass
```

All image-specific envvars can easily be printed out using the [`podman inspect`](https://docs.podman.io/en/stable/markdown/podman-inspect.1.html) command: 

```
podman inspect localhost/swiyu-admin-ch/didtoolbox-java --format='{{json .Config.Env}}' | jq -r '.[]|select(startswith("DIDTOOLBOX_"))'
```

| Image EnvVar             | Description                                                                                                                                                      | Purpose                                                                                                                                                                                   |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| DIDTOOLBOX_BOOTCLASSPATH | Shell interface to the [`-Xbootclasspath/a`](https://docs.oracle.com/en/java/javase/24/docs/specs/man/java.html#extra-options-for-java) option of `java` command | Specifies a directory featuring JAR files to append to the end of the default bootstrap class path.<br><br>Typically used to reference Securosys Primus libs (when working with HSM keys) |
