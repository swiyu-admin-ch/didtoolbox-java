# bin scripts

This directory contains [`podman`](https://docs.podman.io/en/latest/)-based Shell scripts required when running the DID toolbox as Podman image.

Assuming the `mvn package` has already been executed, to create a Podman image featuring the DID toolbox, if not created already, please run: 
```shell
./bin/podman-build.sh
```

So, running the `podman image ls` command right after should result in at least two entries:
```text
REPOSITORY                            TAG         IMAGE ID      CREATED         SIZE
localhost/e-id-admin/didtoolbox-java  latest      0ec11075959c  3 seconds ago  470 MB
docker.io/library/openjdk             23-slim     e419d13420eb  5 months ago   449 MB
```

Finally, once you manage to build a Podman image in your local repo, to run the DID toolbox (as Podman image), please use the `didtoolbox.sh` script, e.g.:

```text
$ ./bin/didtoolbox.sh -h

Usage: didtoolbox [options] [command] [command options]
  Options:
    --help, -h    Display help for the DID toolbox
    --version, -V Display version (default: false)
  Commands:
    create      Create a did:tdw DID and sign the initial DID log entry with the provided private key
      Usage: create [options]
        Options:
          --assert, -a
            An assertion method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
          --auth, -t
            An authentication method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
          --force-overwrite, -f
            Overwrite existing PEM key files, if any
            Default: false
          --help, -h
            Display help for the DID toolbox 'create' command
        * --identifier-registry-url, -u
            A HTTP(S) DID URL (to did.jsonl) to create TDW DID log for
          --jks-alias
            Java KeyStore alias
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore
          --method-version, -m
            Defines the did:tdw specification version to use when generating a DID log. Currently supported is only 'did:tdw:0.3'
            Default: did:tdw:0.3
          --signing-key-file, -s
            The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format
          --verifying-key-file, -v
            The ed25519 public key file(s) for the DID Document’s verification method. One should match the ed25519 private key supplied via -s 
            option. In PEM format

    update      Update a did:tdw DID log by replacing the existing verification material in DID document
      Usage: update [options]
        Options:
          --assert, -a
            An assertion method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
          --auth, -t
            An authentication method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
        * --did-log-file, -d
            The file containing a valid did:tdw DID log to update
          --help, -h
            Display help for the DID toolbox 'update' command
          --jks-alias
            Java KeyStore alias
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore
        * --signing-key-file, -s
            The ed25519 private key file corresponding to the public key, required to sign and output the updated DID log entry. In PEM Format
          --verifying-key-file, -v
            The ed25519 public key file(s) for the DID Document’s verification method. One should match the ed25519 private key supplied via -s 
            option. In PEM format

$ ./bin/didtoolbox.sh -V

didtoolbox 1.2.0
```

Probably the simplest way to use the generator would be to let it generate as much on its own as possible:

```shell
./bin/didtoolbox.sh create -u https://domain.com:443/path1/path2/did.jsonl
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
    -u https://domain.com:443/path1/path2/did.jsonl \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub                                                      
```

As this repo already contains some keys intended for testing purposes, feel free to also try out the following example: 

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com:443/path1/path2/did.jsonl \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias    myalias                                              
```

 Alternatively, besides Java KeyStore (PKCS12) also PEM format of signing/verifying key is supported:

```shell
./bin/didtoolbox.sh create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com:443/path1/path2/did.jsonl \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem
```

So, regardless of whether [verification material](https://www.w3.org/TR/did-core/#verification-material) is generated 
or supplied manually via `-a`/`-t` CLI options, a generated DID log entry will always feature some e.g. the command above 
should produce a following output (_prettified_/_pretty-printed_ version):

```json
[
  "1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM",
  "2025-01-13T13:50:20Z",
  {
    "method": "did:tdw:0.3",
    "scid": "Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH",
    "updateKeys": [
      "z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"
    ]
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id": "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2",
      "authentication": [
        "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01",
          "controller": "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "my-auth-key-01",
            "x": "NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg",
            "y": "Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"
          }
        },
        {
          "id": "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01",
          "controller": "did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "my-assert-key-01",
            "x": "eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ",
            "y": "QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-01-13T13:50:20Z",
      "verificationMethod": "did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP",
      "proofPurpose": "authentication",
      "challenge": "1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM",
      "proofValue": "z3myd1tv3CbGqn8d263dReHyksv3Dud4c2BVXjtBoUNStyHi6xSAg1bN2Ygs25tZdV6xrRcDVjYL1vtTWnLN4ZbMk"
    }
  ]
]
```

The same content _un-prettified_, as it should be found in the `did.jsonl` file:

```json
["1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM","2025-01-13T13:50:20Z",{"method":"did:tdw:0.3","scid":"Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","authentication":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg","y":"Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"}},{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ","y":"QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-01-13T13:50:20Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM","proofValue":"z3myd1tv3CbGqn8d263dReHyksv3Dud4c2BVXjtBoUNStyHi6xSAg1bN2Ygs25tZdV6xrRcDVjYL1vtTWnLN4ZbMk"}]]
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
["1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM","2025-01-13T13:50:20Z",{"method":"did:tdw:0.3","scid":"Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH","updateKeys":["z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","authentication":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"NNkYapGrhRxe_GBOBtF2zLyuDqYPefvJAnmbZIi3Srg","y":"Ee9y-aYqlPdxdJHxqAgznxrplJksL5m7KFMTopBN2Kk"}},{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"eV4ZGw8GUtKOI4mpH5O1cxc_oPJRtbL-u8UzJbtSEHQ","y":"QaNew9zIW6En53YPU4z1FskhdrmTsRPvSO8BUiIaKLY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-01-13T13:50:20Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"1-QmQuX3Yscz1DKw2rN4gtPKZJ3fUsXXy2X7d6iUC63G47NM","proofValue":"z3myd1tv3CbGqn8d263dReHyksv3Dud4c2BVXjtBoUNStyHi6xSAg1bN2Ygs25tZdV6xrRcDVjYL1vtTWnLN4ZbMk"}]]
["2-QmRcms1HYAzrSMc4W1d48ERd33m6guDRsdshkL16HDPXo8","2025-03-21T10:18:50Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","authentication":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01"],"assertionMethod":["did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01"],"verificationMethod":[{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-auth-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-auth-key-01","x":"-MUDoZjNImUbo0vNmdAqhAOPdJoptUC0tlK9xvLrqDg","y":"Djlu_TF69xQF5_L3px2FmCDQksM_fIp6kKbHRQLVIb0"}},{"id":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2#my-assert-key-01","controller":"did:tdw:Qmchhra2pWCauoQz2oBpCurPH5AB8rxkDGtknN5eRAPcTH:domain.com%3A443:path1:path2","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"my-assert-key-01","x":"wdET0dp6vq59s1yyVh_XXyIPPU9Co7PlcTPMRRXx85Y","y":"eThC9-NetN-oXA5WU0Dn0eed7fgHtsXs2E3mU82pA9k"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-03-21T10:18:50Z","verificationMethod":"did:key:z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP#z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP","proofPurpose":"authentication","challenge":"2-QmRcms1HYAzrSMc4W1d48ERd33m6guDRsdshkL16HDPXo8","proofValue":"z2pqJRoc8cB4DEHksgmsgw5RVpNqi4Sx5Jkohpohaomysj3iGrShynsryuArJ7ss5Cfp3eN7zgK7KAA8dSv7FjuST"}]]
```
