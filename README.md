![Public Beta banner](https://github.com/e-id-admin/eidch-public-beta/blob/main/assets/github-banner-publicbeta.jpg)

# DID-Toolbox

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

This project implements the DID-Toolbox, a helper to create DIDs of type Trust DID Web (respectively the renamed method "did:webvh") according to the [specification v.0.3](https://identity.foundation/didwebvh/v0.3/).

## Introduction

A **Decentralized Identifier (DID)** is a globally unique identifier that allows individuals and entities to create and manage their own digital identities independently of centralized authorities. To actively participate in the swiyu Public Beta as an Issuer or Verifier, you must create at least one DID and upload the resulting DID log content to the Identifier Registry. New DIDs can be created using the DID-Toolbox, since it involves a set of steps that are error prone or need some time to get familiar with and one might end up with invalid DIDs.

**Currently, the swiyu ecosystem supports the following DID method: did:tdw, version 0.3.**

As of now, it supports creating DIDs with verification relationships of types (see https://www.w3.org/TR/did-core/#verification-relationships):
- authentication 
- assertionMethod

The DID-Toolbox forces generated DIDs to have at least one key for each verification relationship. One can add multiple keys per verification relationship (see [here](#advanced-usage)).

## Prerequisites

Before using the DID-Toolbox, ensure your system meets the following requirements:

- **Java Runtime Environment (JRE) 21 or Higher:** The DID-Toolbox requires Java JRE version 21 or above. Verify that Java is installed on your machine.
- **Internet Connection:** Required for downloading the tool.
- **Operating System:** Compatible with major operating systems, including Windows, macOS, and Linux. Ensure your OS is up to date to avoid compatibility issues.
- **Sufficient Disk Space:** Allocate enough disk space for the tool and the generated key materials. 100 MB should suffice, depending on the number of DIDs you intend to generate.

## CLI Overview

```text
$ java -jar didtoolbox.jar -h

Usage: didtoolbox [options] [command] [command options]
  Options:
    --help, -h    Display help for the DID toolbox
    --version, -V Display version (default: false)
  Commands:
    create      Create a did:tdw DID Document. Optionally sign the initial log entry if a private key is provided
      Usage: create [options]
        Options:
          --assert, -a
            An assertion method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
          --auth, -t
            An authentication method (comma-separated) parameters: a key name as well as a PEM file containing EC P-256 public/verifying key
          --help, -h
            Display help for the DID toolbox 'create' command
        * --identifier-registry-url, -u
            A HTTP(S) DID URL (to did.jsonl) to create TDW DID log for
          --jks-alias
            Java KeyStore alias
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the keys from
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore
          --method-version, -m
            Defines the did:tdw specification version to use when generating a DID log. Currently supported is only 'did:tdw:0.3'
            Default: did:tdw:0.3
          --signing-key-file, -s
            The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format
          --verifying-key-file, -v
            The ed25519 public key file for the DID Document’s verification method. In PEM format

$ java -jar didtoolbox.jar -h -V

didtoolbox 1.0.0
```

## Quickstart – Create Your First DID

The Quickstart option is designed for users who want to rapidly create one or multiple DIDs without getting too much into the DID method internals. This automates the generation of necessary asymmetric key pairs and builds the initial DID log content, which can be uploaded to the swiyu Identifier Registry.

### Command Syntax

To run the DID-Toolbox using the Quickstart option, use the following command structure:

```shell
$ java -jar didtoolbox.jar create --identifier-registry-url <identifier_registry_url>

# Example
$ java -jar didtoolbox.jar create --identifier-registry-url https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl
```
- **create**: Command to create a new DID
- **<identifier_registry_url>**: URL where the DID is rooted (absolute URL, /did.jsonl is optional)

#### What Happens Upon Execution

- Key Pair Generation: Three key pairs are created and stored in the .didtoolbox directory (output directory, will be created automatically) in PEM format
**Take good care of the generated key material. You will need it again later on (e.g. to configure it in your Issuers and/or Verifiers**:
  - DID Update Key Pair (required to update the DID at a later point in time):
    - id_ed25519: Private key (not password protected)
    - id_ed25519.pem: Public key
  - DID Authentication Key Pair:
    - auth-key-01: Private key (not password protected)
    - auth-key-01.pem: Public key
  - DID Assertion Key Pair:
    - assert-key-01: Private key (not password protected)
    - assert-key-01.pem: Public key
- DID Log Generation: A DID log line is generated and output to the standard console (stdout). You can redirect this output to a file if necessary. This is the output that needs to be uploaded to the swiyu Indentifier Registry.

#### DID Log Content
The generated DID log content should look similiar as shown below. After creation, it consists of a single, albeit lengthy, line.

```json
["1-Qmdc45SbY6miLmcw2EyAysLy2A99TeiQqVXkkyh6qzsLTm","2025-01-07T09:06:06Z",{"method":"did:tdw:0.3","scid":"QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow","updateKeys":["z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE"],"prerotation":false,"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"auth-key-01","x":"CyWSTgeCUzaD4lUWT07vMg-GsTWNOwnEFF7Rfu7OrWU"}},{"id":"did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","kid":"assert-key-01","x":"GTMNlEdWeP-AB40XXG19R57_TUOsgWY4kypRG4ZrQWQ"}}]}},{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-01-07T09:06:06Z","verificationMethod":"did:key:z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE#z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE","proofPurpose":"authentication","challenge":"1-Qmdc45SbY6miLmcw2EyAysLy2A99TeiQqVXkkyh6qzsLTm","proofValue":"z4GG3MaCgwTWH5hEi7C1DyAJzr3VFbfmT9s1PN5Pr4BxgvYSbYsgn5kYAgwxFwXrGC8Wdm45HScq72xkujvPcFhm9"}]
```

Prettified version of the DID log content above.

```json
[
  "1-Qmdc45SbY6miLmcw2EyAysLy2A99TeiQqVXkkyh6qzsLTm",
  "2025-01-07T09:06:06Z",
  {
    "method": "did:tdw:0.3",
    "scid": "QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow",
    "updateKeys": [
      "z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE"
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
      "id": "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "auth-key-01",
            "x": "CyWSTgeCUzaD4lUWT07vMg-GsTWNOwnEFF7Rfu7OrWU"
          }
        },
        {
          "id": "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
          "controller": "did:tdw:QmU49w8drdPUk4g8NXsLqVRqLRz588N99tBSRRBLoxXHow:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "assert-key-01",
            "x": "GTMNlEdWeP-AB40XXG19R57_TUOsgWY4kypRG4ZrQWQ"
          }
        }
      ]
    }
  },
  {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2025-01-07T09:06:06Z",
    "verificationMethod": "did:key:z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE#z6Mkn9mdkU9YnexYS2fqMRkTrpJMBNx344KNb4cAgWFFVWQE",
    "proofPurpose": "authentication",
    "challenge": "1-Qmdc45SbY6miLmcw2EyAysLy2A99TeiQqVXkkyh6qzsLTm",
    "proofValue": "z4GG3MaCgwTWH5hEi7C1DyAJzr3VFbfmT9s1PN5Pr4BxgvYSbYsgn5kYAgwxFwXrGC8Wdm45HScq72xkujvPcFhm9"
  }
]
```

## Advanced Usage

For more control over the DID creation process, you can use specific CLI options to supply your own key material. This repository includes some keys intended for testing purposes. You can use them as follows (**DON'T use DIDs created with those keys, this is soley for educational purposes**):

```shell
$ java -jar didtoolbox.jar create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com:443/path1/path2/did.jsonl \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias myalias                                              
```

 Alternatively, besides Java KeyStore (PKCS #12) also PEM format of signing/verifying key is supported:

```shell
$ java -jar didtoolbox.jar create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com:443/path1/path2/did.jsonl \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem                                              
```

## Additional Information
- **Output Directory**: The `.didtoolbox` directory is automatically created in the current working directory. Ensure you have the necessary permissions to create and write to this directory.
- **Multiple DIDs**: If you create multiple DIDs, please make sure to rename the `.didtoolbox` directory (or move/rename the files) after each creation run, since the key material will re-generated on each run and therefore overwritten.
- **Security**: Keep your private keys secure. Do not share them or expose them in unsecured environments.
- **Using Existing DIDs**: While the Quickstart option generates new DIDs and key material, future versions of the DID-Toolbox may support importing and managing existing DIDs. 

## Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for contributing found in [CONTRIBUTING](./CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for details.
