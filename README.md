![swiyu GitHub banner](https://github.com/swiyu-admin-ch/swiyu-admin-ch.github.io/blob/main/assets/images/github-banner.jpg)

# DID-Toolbox

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

This project implements the DID-Toolbox, a helper to create DIDs of type Trust DID Web (respectively the renamed method "did:webvh") according to the [specification v0.3](https://identity.foundation/didwebvh/v0.3/).

## Table of contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [CLI Overview](#cli-overview)
- [Quickstart – Create Your First DID](#quickstart--create-your-first-did)
- [Update an existing DID](#update-an-existing-did)
- [Advanced Usage](#advanced-usage)
  - [Create](#did-creation)
  - [Update](#did-update)
- [Additional Information](#additional-information)
- [Known Issues](#known-issues)
- [Contributions and Feedback](#contributions-and-feedback)
- [License](#license)

## Introduction

A **Decentralized Identifier (DID)** is a globally unique identifier that allows individuals and entities to create and manage their own digital identities independently of centralized authorities. To actively participate in the swiyu Public Beta as an issuer or verifier, you must create at least one DID and upload the resulting DID log content to the Identifier Registry. Creating new DIDs involves a set of steps that are error prone or need some time to get familiar with and one might end up with invalid DIDs. The DID-Toolbox supports you with various options for a quick start or advanced usage.

**Currently, the swiyu ecosystem supports the following DID method: did:tdw, version 0.3.**

As of now, it supports creating and updating DIDs with [verification relationships](https://www.w3.org/TR/did-core/#verification-relationships) of types:
- authentication 
- assertionMethod

The DID-Toolbox forces generated DIDs to have at least one key for each verification relationship. One can add multiple keys per verification relationship as well as add and/or remove keys by updating an previously generated DID (see [here](#advanced-usage)).

## Prerequisites

Before using the DID-Toolbox, ensure your system meets the following requirements:

- **Operating System:** Compatible with the following operating systems: Linux (x86-64 & AArch64), macOS (AArch64) and Windows (x86-64). Ensure your OS is up to date to avoid compatibility issues.
- **Java Runtime Environment (JRE) 21 or Higher:** The DID-Toolbox requires Java JRE version 21 or above. Verify that Java is installed on your machine. JNA support is required, since the DID-Toolbox depends on another, platform dependent library, used to verify the generated DID log outputs.
- **Internet Connection:** Required for downloading the tool.
- **Sufficient Disk Space:** Allocate enough disk space for the tool and the generated key materials. 100 MB should suffice, depending on the number of DIDs you intend to generate.
- **Third-party JCE provider library (OPTIONAL, only in case of Securosys Primus HSM as the source of signing/verifying key pair):** 
In this case, the required JCE provider (JAR) library is available for download [here](https://nexus.bit.admin.ch/#browse/browse:bit-pki-raw-hosted:securosys%2Fjce) or (alternatively) [here](https://docs.securosys.com/jce/Downloads/).
Once downloaded, the relevant JAR file (`primusX-java8.jar` or `primusX-java11.jar`) is then expected to be stored on the system alongside the DID-Toolbox in the `lib` subdirectory (e.g. as `lib/primusX-java11.jar`).
Beware that running the DID-Toolbox with `--primus-*` CLI parameters supplied will inevitably/unconditionally fail if none of these libraries is available on the system. 

## CLI Overview

```text
$ java -jar didtoolbox.jar -h

Usage: didtoolbox [options] [command] [command options]
  Options:
    --help, -h    Display help for the DID toolbox
    --version, -V Display version (default: false)
  Commands:
    create      Create a did:tdw DID and sign the initial DID log entry with the provided private key. To supply a signing/verifying key pair, always 
            rely on one of the three available command parameter sets exclusively, each of then denoting a whole another source of such key material: 
            PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the required 
            JCE provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox in 
            the lib subdirectory (e.g. as lib/primusX-java11.jar)
      Usage: create [options]
        Options:
          --assert, -a
            One or more assertion method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 
            public/verifying key
          --auth, -t
            One or more authentication method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC 
            P-256 public/verifying key
          --force-overwrite, -f
            Overwrite existing PEM key files, if any
            Default: false
          --help, -h
            Display help for the DID toolbox command
        * --identifier-registry-url, -u
            A HTTP(S) DID URL (to did.jsonl) to create TDW DID log for
          --jks-alias
            Java KeyStore alias name of the entry to process. This CLI parameter should always be used exclusively alongside all the other --jks-* 
            CLI parameters
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. This CLI parameter should always be used exclusively alongside all 
            the other --jks-* CLI parameters
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. This CLI parameter should 
            always be used exclusively alongside all the other --jks-* CLI parameters
          --method-version, -m
            Defines the did:tdw specification version to use when generating a DID log. Currently supported is only 'did:tdw:0.3'
            Default: did:tdw:0.3
          --primus-credentials, -p
            A safely stored credentials file required when using (signing/verifying) keys available in the Securosys Primus (HSM) Keystore. It should 
            feature a quartet of the following properties: securosys_primus_host, securosys_primus_port, securosys_primus_user and 
            securosys_primus_password. Any credential missing in this file will simply fallback to its system environment counterpart (if set) - the 
            relevant envvars in this case are: SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER and SECUROSYS_PRIMUS_PASSWORD. 
            This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-alias, -q
            An alias the (signing/verifying) key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. This CLI parameter should 
            always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-password
            An optional password required for recovering the (signing/verifying) key pair (stored in Securosys Primus (HSM) Keystore). This CLI 
            parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --signing-key-file, -s
            The ed25519 private key file required to sign a DID log entry. In PEM Format. This CLI parameter cannot be used in conjunction with any 
            of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.

    update      Update a did:tdw DID log by replacing the existing verification material in DID document. To supply a signing/verifying key pair, 
            always rely on one of the three available command parameter sets exclusively, each of then denoting a whole another source of such key 
            material: PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the 
            required JCE provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the 
            DID-Toolbox in the lib subdirectory (e.g. as lib/primusX-java11.jar)
      Usage: update [options]
        Options:
          --assert, -a
            One or more assertion method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 
            public/verifying key
          --auth, -t
            One or more authentication method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC 
            P-256 public/verifying key
        * --did-log-file, -d
            The file containing a valid did:tdw DID log to update
          --help, -h
            Display help for the DID toolbox command
          --jks-alias
            Java KeyStore alias name of the entry to process. This CLI parameter should always be used exclusively alongside all the other --jks-* 
            CLI parameters
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. This CLI parameter should always be used exclusively alongside all 
            the other --jks-* CLI parameters
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. This CLI parameter should 
            always be used exclusively alongside all the other --jks-* CLI parameters
          --primus-credentials, -p
            A safely stored credentials file required when using (signing/verifying) keys available in the Securosys Primus (HSM) Keystore. It should 
            feature a quartet of the following properties: securosys_primus_host, securosys_primus_port, securosys_primus_user and 
            securosys_primus_password. Any credential missing in this file will simply fallback to its system environment counterpart (if set) - the 
            relevant envvars in this case are: SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER and SECUROSYS_PRIMUS_PASSWORD. 
            This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-alias, -q
            An alias the (signing/verifying) key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. This CLI parameter should 
            always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-password
            An optional password required for recovering the (signing/verifying) key pair (stored in Securosys Primus (HSM) Keystore). This CLI 
            parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --signing-key-file, -s
            The ed25519 private key file required to sign a DID log entry. In PEM Format. This CLI parameter cannot be used in conjunction with any 
            of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.

    deactivate      Deactivate (revoke) a did:tdw DID log. To supply a signing/verifying key pair, always rely on one of the three available command 
            parameter sets exclusively, each of then denoting a whole another source of such key material: PEM files, a Java KeyStore (PKCS12) or a 
            Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library 
            (primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox in the lib subdirectory (e.g. 
            as lib/primusX-java11.jar)
      Usage: deactivate [options]
        Options:
        * --did-log-file, -d
            The file containing a valid did:tdw DID log to deactivate
          --help, -h
            Display help for the DID toolbox command
          --jks-alias
            Java KeyStore alias name of the entry to process. This CLI parameter should always be used exclusively alongside all the other --jks-* 
            CLI parameters
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. This CLI parameter should always be used exclusively alongside all 
            the other --jks-* CLI parameters
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. This CLI parameter should 
            always be used exclusively alongside all the other --jks-* CLI parameters
          --primus-credentials, -p
            A safely stored credentials file required when using (signing/verifying) keys available in the Securosys Primus (HSM) Keystore. It should 
            feature a quartet of the following properties: securosys_primus_host, securosys_primus_port, securosys_primus_user and 
            securosys_primus_password. Any credential missing in this file will simply fallback to its system environment counterpart (if set) - the 
            relevant envvars in this case are: SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER and SECUROSYS_PRIMUS_PASSWORD. 
            This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-alias, -q
            An alias the (signing/verifying) key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. This CLI parameter should 
            always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --primus-keystore-password
            An optional password required for recovering the (signing/verifying) key pair (stored in Securosys Primus (HSM) Keystore). This CLI 
            parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)
          --signing-key-file, -s
            The ed25519 private key file required to sign a DID log entry. In PEM Format. This CLI parameter cannot be used in conjunction with any 
            of --jks-* or --primus-* CLI parameters

$ java -jar didtoolbox.jar -V

didtoolbox 1.4.0
```

## Quickstart – Create Your First DID

The quickstart option is designed for users who want to rapidly create one or multiple DIDs without getting too much into the DID method internals. This automates the generation of necessary asymmetric key pairs and builds the initial DID log content, which can be uploaded to the swiyu Identifier Registry.

### Command Syntax

To run the DID-Toolbox using the Quickstart option, use the following command structure:

```shell
$ java -jar didtoolbox.jar create --identifier-registry-url <identifier_registry_url>

# Example
$ java -jar didtoolbox.jar create --identifier-registry-url https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085
```
- **create**: Command to create a new DID
- **<identifier_registry_url>**: URL where the DID is rooted (absolute URL, /did.jsonl is optional)

#### What Happens Upon Execution

- Key Pair Generation: Three key pairs are created and stored in the .didtoolbox directory (output directory, will be created automatically) in PEM format.
**Take good care of the generated key material. You will need it again later on (e.g. to configure it in your Issuers and/or Verifiers**):
  - DID Update Key Pair (required to update the DID at a later point in time):
    - id_ed25519: Private key (not password protected)
    - id_ed25519.pem: Public key
  - DID Authentication Key Pair:
    - auth-key-01: Private key (not password protected)
    - auth-key-01.pem: Public key
  - DID Assertion Key Pair:
    - assert-key-01: Private key (not password protected)
    - assert-key-01.pem: Public key
- DID Log Generation: A DID log line is generated and output to the standard console (stdout). You can redirect this output to a file if necessary. This is the output that needs to be uploaded to the swiyu Identifier Registry.

#### DID Log Content
The generated DID log content should look similar as shown below. After creation, it consists of a single, albeit lengthy, line.

```json
["1-QmRdMTkEvFsfkFv8eJp9nUWnecXF3EzDQJhuetHMTVMFdg","2025-03-21T07:38:51Z",{"method":"did:tdw:0.3","scid":"Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK","updateKeys":["z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"5cice-6ILYCD2gFEVFMLPt3HPf5n_OefzOOoP-3SLDA","y":"lh_YkKQvF_1xv0uYuvy1t6wpDM7au1dMEg2L1I9wDxE","kid":"auth-key-01"}},{"id":"did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"Z4Hp-L-THKPCUQqYOyICAU7YekPsYwOjrLaiOW_EdXk","y":"tF0NJM4B5J85zFtvgHNtnk6pV7VY52GAq0nppq2Pop0","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-03-21T07:38:51Z","verificationMethod":"did:key:z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC#z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC","proofPurpose":"authentication","challenge":"1-QmRdMTkEvFsfkFv8eJp9nUWnecXF3EzDQJhuetHMTVMFdg","proofValue":"z4yxZfm1nG6AerU5Mg3yrrvqn2mmMRjMJC4999BunnS3hg9SVjicugw8ZWEJYsQkarypDNRAqAjo48bH42ekyMa1c"}]]
```

Prettified version of the DID log content above.

```json
[
  "1-QmRdMTkEvFsfkFv8eJp9nUWnecXF3EzDQJhuetHMTVMFdg",
  "2025-03-21T07:38:51Z",
  {
    "method": "did:tdw:0.3",
    "scid": "Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK",
    "updateKeys": [
      "z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC"
    ],
    "portable": false
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/jwk/v1"
      ],
      "id": "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "5cice-6ILYCD2gFEVFMLPt3HPf5n_OefzOOoP-3SLDA",
            "y": "lh_YkKQvF_1xv0uYuvy1t6wpDM7au1dMEg2L1I9wDxE",
            "kid": "auth-key-01"
          }
        },
        {
          "id": "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
          "controller": "did:tdw:Qmd9bwsodZ1GAz4h8D7Vy6qRio78voXifDrnXokSTsMVQK:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "Z4Hp-L-THKPCUQqYOyICAU7YekPsYwOjrLaiOW_EdXk",
            "y": "tF0NJM4B5J85zFtvgHNtnk6pV7VY52GAq0nppq2Pop0",
            "kid": "assert-key-01"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-03-21T07:38:51Z",
      "verificationMethod": "did:key:z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC#z6MknjdKazKDMB66puMBqbMkg5uR834Mr51RYtmdBC9JFvFC",
      "proofPurpose": "authentication",
      "challenge": "1-QmRdMTkEvFsfkFv8eJp9nUWnecXF3EzDQJhuetHMTVMFdg",
      "proofValue": "z4yxZfm1nG6AerU5Mg3yrrvqn2mmMRjMJC4999BunnS3hg9SVjicugw8ZWEJYsQkarypDNRAqAjo48bH42ekyMa1c"
    }
  ]
]
```

## Update an existing DID
Currently, we can't guarantee, that a DID generated without the help of the DID-Toolbox can be updated successfully. To keep matters simple, a user needs to supply all the key material (assertion and authentication public keys) that should be contained in the updated version of a DID.
For illustration purposes, we will generate a new DID and perform an assert key rotation by removing the initial assertion key and adding a new one.

```shell
# Step 1 - Generate new DID and redirect stdout to v01_did.jsonl file (contains the created DID log)
$ java -jar didtoolbox.jar create -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085 > v01_did.jsonl

# Step 2 - Rename the generated .didtoobox folder to make sure the initially generated key material remains accessible
$ mv .didtoolbox .didtoolbox_keys_v01

# Step 3 - To keep it simple, create a new dummy DID so that we get a new set of key material (we're interested in the assertion key for the sake of this example). No stdout redirect required, since we're only aiming for the key material that will be generated in the .didtoolbox directory.
$ java -jar didtoolbox.jar create -u https://example.com

# Step 4 - Update the DID from step 1, so that the assert key is rotated to a new one while the previous one is removed. We'll keep the authentication key. Redirect stdout to v02_did.jsonl file (contains the updated DID log, now with two versions)
$ java -jar didtoolbox.jar update -d v01_did.jsonl -s .didtoolbox_keys_v01/id_ed25519 -v .didtoolbox_keys_v01/id_ed25519.pub -a assert-key-02,.didtoolbox/assert-key-01.pub -t auth-key-01,.didtoolbox_keys_v01/assert-key-01.pub > v02_did.jsonl
# -d to supply the initial DID log file of the DID to be updated (v01_did.jsonl)
# -s to supply a valid updateKey private keyfile (PEM) required to generate the proof of the new DID log line (.didtoolbox_keys_v01/id_ed25519)
# -v to supply a the matching updateKey public keyfile (PEM) (.didtoolbox_keys_v01/id_ed25519.pub)
# -a to supply the fragment name and assertion public key that the updated DID should contain (.didtoolbox/assert-key-01.pub)
# -t to keep the authentication public key (auth-key-01,.didtoolbox_keys_v01/assert-key-01.pub) in the updated DID

```

The updated DID log file (v02_did.jsonl) should contain two lines, each containing one DID version

```
["1-QmcJJMcAhY1t2DUPEDCRTQGohUq7t8b5vS3yqctMcchtGi","2025-03-31T12:59:30Z",{"method":"did:tdw:0.3","scid":"QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9","updateKeys":["z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg"],"portable":false},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"j8C2kkSg1wyxhLjxRTy7jW8Bc2V8gPAFD6ophpHpPRw","y":"Zr1xbFYdj8lvrZXDLi57f_dAIgANX2EBWqftQbmq_f8","kid":"auth-key-01"}},{"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE","y":"jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-03-31T12:59:30Z","verificationMethod":"did:key:z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg#z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg","proofPurpose":"authentication","challenge":"1-QmcJJMcAhY1t2DUPEDCRTQGohUq7t8b5vS3yqctMcchtGi","proofValue":"z4fmECdwJHXynwZcVYYGtipG5g5ZuzhABUph9SmDJzjSuqQM7Uhp8Mpk4gNNFUiMyzJ7gYDjTDqp7BiEiPJNrzkje"}]]
["2-Qmbad4Gygs74r1yprZ787YC8NcarfpK5SYu7cAHZBRpE1d","2025-03-31T13:00:51Z",{},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"],"verificationMethod":[{"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"auth-key-01","x":"3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE","y":"jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"}},{"id":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02","controller":"did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert-key-02","x":"Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8","y":"A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-03-31T13:00:51Z","verificationMethod":"did:key:z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg#z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg","proofPurpose":"authentication","challenge":"2-Qmbad4Gygs74r1yprZ787YC8NcarfpK5SYu7cAHZBRpE1d","proofValue":"z5wp8P8RA7SEG3hmtewv7kpiZWvuDfvP6wM6vK1744CyJWVdSsr8YVJ5SHRVW9N6mdQ2oL2bXaSQearSvEfLQes52"}]]
```

Prettified initial version (version 1) of the created DID (line 1 of v02_did.jsonl)

```json
[
  "1-QmcJJMcAhY1t2DUPEDCRTQGohUq7t8b5vS3yqctMcchtGi",
  "2025-03-31T12:59:30Z",
  {
    "method": "did:tdw:0.3",
    "scid": "QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9",
    "updateKeys": [
      "z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg"
    ],
    "portable": false
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/jwk/v1"
      ],
      "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "j8C2kkSg1wyxhLjxRTy7jW8Bc2V8gPAFD6ophpHpPRw",
            "y": "Zr1xbFYdj8lvrZXDLi57f_dAIgANX2EBWqftQbmq_f8",
            "kid": "auth-key-01"
          }
        },
        {
          "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
          "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
            "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y",
            "kid": "assert-key-01"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-03-31T12:59:30Z",
      "verificationMethod": "did:key:z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg#z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg",
      "proofPurpose": "authentication",
      "challenge": "1-QmcJJMcAhY1t2DUPEDCRTQGohUq7t8b5vS3yqctMcchtGi",
      "proofValue": "z4fmECdwJHXynwZcVYYGtipG5g5ZuzhABUph9SmDJzjSuqQM7Uhp8Mpk4gNNFUiMyzJ7gYDjTDqp7BiEiPJNrzkje"
    }
  ]
]
```
Prettified version 2 of the DID (line 2 of v02_did.jsonl)

```json
[
  "2-Qmbad4Gygs74r1yprZ787YC8NcarfpK5SYu7cAHZBRpE1d",
  "2025-03-31T13:00:51Z",
  {},
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/jwk/v1"
      ],
      "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "auth-key-01",
            "x": "3-xR-ApvKYCKtXxjvypxIb4tHJSUTHCl0uUYVAvP6sE",
            "y": "jkQdXwStFmrJjHuWw8PE_AG43c4OQwd6-Rkr4sPiC7Y"
          }
        },
        {
          "id": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
          "controller": "did:tdw:QmNvrTSTX4ix7ykYHrdf4rsN9MNJEy6c8TMk6C4uPjY1h9:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "assert-key-02",
            "x": "Ja4P63oUfaUageuu9O_6kOHT6bLe5D4myacZpEICwC8",
            "y": "A4JwAyrpKxtsNLX50A0pQ_4G2AYO-NJw0dzne11xUj0"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-03-31T13:00:51Z",
      "verificationMethod": "did:key:z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg#z6MkgQsLSodAq9kwYWBfEYoHA3GZs747zGPRoCisHJZX7Xgg",
      "proofPurpose": "authentication",
      "challenge": "2-Qmbad4Gygs74r1yprZ787YC8NcarfpK5SYu7cAHZBRpE1d",
      "proofValue": "z5wp8P8RA7SEG3hmtewv7kpiZWvuDfvP6wM6vK1744CyJWVdSsr8YVJ5SHRVW9N6mdQ2oL2bXaSQearSvEfLQes52"
    }
  ]
]
```

## Advanced Usage

### DID Creation

For more control over the DID creation process, you can use specific CLI options to supply your own key material. This repository includes some keys intended for testing purposes. You can use them as follows (**DON'T use DIDs created with those keys, this is only for educational purposes**):

```shell
$ java -jar didtoolbox.jar create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com/path1/path2 \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias myalias                                              
```

 Alternatively, besides Java KeyStore (PKCS #12) also PEM format of signing/verifying key is supported:

```shell
$ java -jar didtoolbox.jar create \
    -a my-assert-key-01,src/test/data/assert-key-01.pub \
    -t my-auth-key-01,src/test/data/auth-key-01.pub \
    -u https://domain.com/path1/path2 \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem                                              
```

### DID Update

Once a newly created `did.jsonl` file is available, you may use the `update` subcommand at any point to **completely**
replace the existing [verification material](https://www.w3.org/TR/did-core/#verification-material) in DID document:

```shell
java -jar didtoolbox.jar create \
    -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did18fa7c77-9dd1-4e20-a147-fb1bec146085 > /tmp/my-did.jsonl

# bear in mind, the command above will store the generated (auth/assert) keys in the .didtoolbox directory

java -jar didtoolbox.jar update \
    -d /tmp/did.jsonl \
    -a my-assert-key-01,.didtoolbox/assert-key-01.pub \
    -t my-auth-key-01,.didtoolbox/auth-key-01.pub \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub > /tmp/did-2.jsonl
```

### DID Deactivation (Revoke)

Once a created `did.jsonl` file is available, you may also use the `deactivate` subcommand at any point to 
[**deactivate (revoke)**](https://identity.foundation/didwebvh/v0.3/#deactivate-revoke) this DID:

```shell
java -jar didtoolbox.jar create \
    -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did18fa7c77-9dd1-4e20-a147-fb1bec146085 > /tmp/my-did.jsonl

# bear in mind, the command above will store the generated (auth/assert) keys in the .didtoolbox directory

java -jar didtoolbox.jar deactivate \
    -d /tmp/did.jsonl \
    -s .didtoolbox/id_ed25519 > /tmp/did-deactivated.jsonl
```

The _deactivated_ DID log file should now contain another DID log entry denoting deactivation (via DID parameter `{"deactivated":true}`) and featuring no key material whatsoever: 

```json
["2-QmbSZkkCbUFr2EmX2Zop8oBHybrxmoALYjrByK7mEgh19p","2025-06-10T15:33:28Z",{"deactivated":true,"updateKeys":[]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:tdw:QmSavPQAAUPaC41G71t5i2ePacgJVQHwHHupchM5J2pZLX:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085"}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-06-10T15:33:28Z","verificationMethod":"did:key:z6MkrsVnXojRZPSVdHL4CwmwjKkEAAnzj88FhyJcDM2AimnA#z6MkrsVnXojRZPSVdHL4CwmwjKkEAAnzj88FhyJcDM2AimnA","proofPurpose":"authentication","challenge":"2-QmbSZkkCbUFr2EmX2Zop8oBHybrxmoALYjrByK7mEgh19p","proofValue":"z5JeoxtuHruBHZ2NcnKgS2Xbz9TY2zqS1jETHY8xmwvLQRp4FMCtVm6zcXkwMat1g88k8oYqS6PPbA7mwwrpDmoUv"}]]
```

## Additional Information
- **Output Directory**: When creating new DIDs, the `.didtoolbox` directory is automatically created in the current working directory. Ensure you have the necessary permissions to create and write to this directory.
- **Multiple DIDs**: If you create multiple DIDs, please make sure to rename the `.didtoolbox` directory (or move/rename the files) after each creation run. The DID-Toolbox will prevent you from overwriting existing key pairs by accident and abort with an error.
- **Security**: Keep your private keys secure. Do not share them or expose them in unsecured environments.
- **Credentials file (e.g. in case of using Securosys Primus HSM):** Keep such files safely stored on the file system.
Alternatively, you may also fallback to a system user environment, instead.

## Known Issues

The swiyu Public Beta Trust Infrastructure was deliberately released at an early stage to enable future ecosystem participants. There may still be minor bugs or security vulnerabilities in the test system. We will publish them in the near future as ‘KnownIssues’ in this repository.

## Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for contributing found in [CONTRIBUTING](./CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for details.
