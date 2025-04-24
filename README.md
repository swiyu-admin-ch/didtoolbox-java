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

- **Operating System:** Compatible with the following operating systems: Windows (x86-64), macOS (ARM64), and Linux (x86-64). Ensure your OS is up to date to avoid compatibility issues.
- **Java Runtime Environment (JRE) 21 or Higher:** The DID-Toolbox requires Java JRE version 21 or above. Verify that Java is installed on your machine. JNA support is required, since the DID-Toolbox depends on another, platform dependent library, used to verify the generated DID log outputs.
- **Internet Connection:** Required for downloading the tool.
- **Sufficient Disk Space:** Allocate enough disk space for the tool and the generated key materials. 100 MB should suffice, depending on the number of DIDs you intend to generate.
- **Third-party JCE provider library (OPTIONAL, only in case of Securosys Primus HSM as the source of signing/verifying key pair):** 
In this case, the required JCE provider (JAR) library is available for download [here](https://nexus.bit.admin.ch/#browse/browse:bit-pki-raw-hosted:securosys%2Fjce) or (alternatively) [here](https://docs.securosys.com/jce/Downloads/).
Once downloaded, the relevant JAR file (`primusX-java8.jar` or `primusX-java11.jar`) is then expected to be stored on the system alongside the DID-Toolbox,
more specifically in the `lib` subdirectory. e.g. as `lib/primusX-java11.jar`.
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
            JCE provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the DID-Toolbox, 
            more specifically in the lib subdirectory, e.g. as lib/primusX-java11.jar
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
          --primus-keystore, -p
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
            The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format. This 
            CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            The ed25519 public key file(s) for the DID Document’s verification method. One should match the ed25519 private key supplied via -s 
            option. In PEM format. This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters

    update      Update a did:tdw DID log by replacing the existing verification material in DID document. To supply a signing/verifying key pair, 
            always rely on one of the three available command parameter sets exclusively, each of then denoting a whole another source of such key 
            material: PEM files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the 
            required JCE provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is expected to be stored on the system alongside the 
            DID-Toolbox, more specifically in the lib subdirectory, e.g. as lib/primusX-java11.jar
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
            Java KeyStore alias name of the entry to process. This CLI parameter should always be used exclusively alongside all the other --jks-* 
            CLI parameters
          --jks-file, -j
            Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. This CLI parameter should always be used exclusively alongside all 
            the other --jks-* CLI parameters
          --jks-password
            Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. This CLI parameter should 
            always be used exclusively alongside all the other --jks-* CLI parameters
          --primus-keystore, -p
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
            The ed25519 private key file corresponding to the public key, required to sign and output the initial DID log entry. In PEM Format. This 
            CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            The ed25519 public key file(s) for the DID Document’s verification method. One should match the ed25519 private key supplied via -s 
            option. In PEM format. This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters

$ java -jar didtoolbox.jar -V

didtoolbox 1.3.0
```

## Quickstart – Create Your First DID

The quickstart option is designed for users who want to rapidly create one or multiple DIDs without getting too much into the DID method internals. This automates the generation of necessary asymmetric key pairs and builds the initial DID log content, which can be uploaded to the swiyu Identifier Registry.

### Command Syntax

To run the DID-Toolbox using the Quickstart option, use the following command structure:

```shell
$ java -jar didtoolbox.jar create --identifier-registry-url <identifier_registry_url>

# Example
$ java -jar didtoolbox.jar create --identifier-registry-url https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl
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
["1-QmZJLegQtzHoLJN18Qv8NBpUuHDZambgkNtTiSpLf9KJMn","2025-02-27T13:06:59Z",{"method":"did:tdw:0.3","scid":"Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5","updateKeys":["z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"c_3s3uuQ0uBAlm_b1COp3Z_gc4hSkD65OOeeoMYDZbI","y":"OJbcwriVbIATAmdEnMujF3D0VdhyS4MgLr4FVQyu9_4","kid":"auth-key-01"}},{"id":"did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"rGbmDnKImy5Mpmg7zs6w-BI1Jad2A13aRK6fyOdQhGA","y":"XuiCtjOHLhMWpGlZH7pYQtGCVo5xqNUef2xxDmB-u3Q","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-02-27T13:06:59Z","verificationMethod":"did:key:z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR#z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR","proofPurpose":"authentication","challenge":"1-QmZJLegQtzHoLJN18Qv8NBpUuHDZambgkNtTiSpLf9KJMn","proofValue":"z4UgxtS8T64H6aG8VSbRcdJMcSoN5FtrFABQrMHTHQim3nXrfFJdoiQg7QqVvbSp6wSY2JH39B53UtMyvquWrGwDu"}]]

```

Prettified version of the DID log content above.

```json
[
  "1-QmZJLegQtzHoLJN18Qv8NBpUuHDZambgkNtTiSpLf9KJMn",
  "2025-02-27T13:06:59Z",
  {
    "method": "did:tdw:0.3",
    "scid": "Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5",
    "updateKeys": [
      "z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR"
    ]
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id": "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "c_3s3uuQ0uBAlm_b1COp3Z_gc4hSkD65OOeeoMYDZbI",
            "y": "OJbcwriVbIATAmdEnMujF3D0VdhyS4MgLr4FVQyu9_4",
            "kid": "auth-key-01"
          }
        },
        {
          "id": "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
          "controller": "did:tdw:Qmc8e3ZUSFw7UE7uq4xWPKYpKvRfzyM5w4qwMALZo2ScH5:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "rGbmDnKImy5Mpmg7zs6w-BI1Jad2A13aRK6fyOdQhGA",
            "y": "XuiCtjOHLhMWpGlZH7pYQtGCVo5xqNUef2xxDmB-u3Q",
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
      "created": "2025-02-27T13:06:59Z",
      "verificationMethod": "did:key:z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR#z6MkrmdqL3gtwVQtHHi3NUpLuPoW9gHjwooq9dSFbRDWFAQR",
      "proofPurpose": "authentication",
      "challenge": "1-QmZJLegQtzHoLJN18Qv8NBpUuHDZambgkNtTiSpLf9KJMn",
      "proofValue": "z4UgxtS8T64H6aG8VSbRcdJMcSoN5FtrFABQrMHTHQim3nXrfFJdoiQg7QqVvbSp6wSY2JH39B53UtMyvquWrGwDu"
    }
  ]
]
```

## Update an existing DID
Currently, we can't guarantee, that a DID generated without the help of the DID-Toolbox can be updated successfully. To keep matters simple, a user needs to supply all the key material (assertion and authentication public keys) that should be contained in the updated version of a DID.
For illustration purposes, we will generate a new DID and perform an assert key rotation by removing the initial assertion key and adding a new one.

```shell
# Step 1 - Generate new DID and redirect stdout to v01_did.jsonl file (contains the created DID log)
$ java -jar didtoolbox.jar create -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl > v01_did.jsonl

# Step 2 - Rename the generated .didtoobox folder to make sure the initially generated key material remains accessible
$ mv .didtoolbox .didtoolbox_keys_v01

# Step 3 - To keep it simple, create a new dummy DID so that we get a new set of key material (we're interested in the assertion key for the sake of this example). No stdout redirect required, since we're only aiming for the key material that will be generated in the .didtoolbox directory.
$ java -jar didtoolbox.jar create -u https://example.com/did.jsonl

# Step 4 - Update the DID from step 1, so that the assert key is rotated to a new one while the previous one is removed. We'll keep the authentication key. Redirect stdout to v02_did.jsonl file (contains the updated DID log, now wth two versions)
$ java -jar didtoolbox.jar update -d v01_did.jsonl -s .didtoolbox_keys_v01/id_ed25519 -v .didtoolbox_keys_v01/id_ed25519.pub -a assert-key-02,.didtoolbox/assert-key-01.pub -t auth-key-01,.didtoolbox_keys_v01/assert-key-01.pub > v02_did.jsonl
# -d to supply the initial DID log file of the DID to be updated (v01_did.jsonl)
# -s to supply a valid updateKey private keyfile (PEM) required to generate the proof of the new DID log line (.didtoolbox_keys_v01/id_ed25519)
# -v to supply a the matching updateKey public keyfile (PEM) (.didtoolbox_keys_v01/id_ed25519.pub)
# -a to supply the fragment name and assertion public key that the updated DID should contain (.didtoolbox/assert-key-01.pub)
# -t to keep the authentication public key (auth-key-01,.didtoolbox_keys_v01/assert-key-01.pub) in the updated DID

```

The updated DID log file (v02_did.jsonl) should contain two lines, each containing one DID version

```
["1-QmU2vJpqQsC7DQRSR9UhMGJ9E6XdFS21E1y7Hv5kjzvUGm","2025-02-27T13:42:46Z",{"method":"did:tdw:0.3","scid":"QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo","updateKeys":["z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8"]},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"hELL9Z-5rkg8p8IY04pogDhtNML-xz79MDnOLRJE3n8","y":"4jCz1BwmqWgMDAyp1CRzmm28syN4aH1FvFRjgEyAHK0","kid":"auth-key-01"}},{"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","controller":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"ngddzGFoi-yZDqasoBX8zvFO73rCHPCQcGVEiLVka3Y","y":"v3x-KtZMZD7FZgT2dh-xwVriocHldTRKaijMvnwV4bQ","kid":"assert-key-01"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-02-27T13:42:46Z","verificationMethod":"did:key:z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8#z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8","proofPurpose":"authentication","challenge":"1-QmU2vJpqQsC7DQRSR9UhMGJ9E6XdFS21E1y7Hv5kjzvUGm","proofValue":"z57X6vPoLKGWfTT8iCp7kD7eRNKuykcNYujbVrXeWqFe8WDc3GUBGvCxbdq5u6m4ZE7WNVM4zedxnVVzLozkcKWXE"}]]
["2-QmSwrQpiTmTZrbJPF8q8viuqaZ1ZdxsU5um4zeZ8FbzEw9","2025-02-27T13:44:33Z",{"witnessThreshold":0},{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/suites/jws-2020/v1"],"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"],"verificationMethod":[{"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","controller":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"auth-key-01","x":"ngddzGFoi-yZDqasoBX8zvFO73rCHPCQcGVEiLVka3Y","y":"v3x-KtZMZD7FZgT2dh-xwVriocHldTRKaijMvnwV4bQ"}},{"id":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02","controller":"did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert-key-02","x":"7d802vPuAZ-8SyEuTdfCE03-0YeHtrrO4DqcJPRJ8L4","y":"pQsxkJETgGFaz3szf962_e1SMVTUAypKx-Fd7KPA3K4"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-02-27T13:44:33Z","verificationMethod":"did:key:z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8#z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8","proofPurpose":"authentication","challenge":"2-QmSwrQpiTmTZrbJPF8q8viuqaZ1ZdxsU5um4zeZ8FbzEw9","proofValue":"z5ZoqFzYDx2kPPTKAv6kjYAL3SpTqU4UFfRu9i4Xy1ioorGQAV5T3U7qAADe5EhjH3tdaWEpV7qGPQMaJF24vq6Qg"}]]
```

Prettified initial version (version 1) of the created DID (line 1 of v02_did.jsonl)

```json
[
  "1-QmU2vJpqQsC7DQRSR9UhMGJ9E6XdFS21E1y7Hv5kjzvUGm",
  "2025-02-27T13:42:46Z",
  {
    "method": "did:tdw:0.3",
    "scid": "QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo",
    "updateKeys": [
      "z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8"
    ]
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "hELL9Z-5rkg8p8IY04pogDhtNML-xz79MDnOLRJE3n8",
            "y": "4jCz1BwmqWgMDAyp1CRzmm28syN4aH1FvFRjgEyAHK0",
            "kid": "auth-key-01"
          }
        },
        {
          "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
          "controller": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "ngddzGFoi-yZDqasoBX8zvFO73rCHPCQcGVEiLVka3Y",
            "y": "v3x-KtZMZD7FZgT2dh-xwVriocHldTRKaijMvnwV4bQ",
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
      "created": "2025-02-27T13:42:46Z",
      "verificationMethod": "did:key:z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8#z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8",
      "proofPurpose": "authentication",
      "challenge": "1-QmU2vJpqQsC7DQRSR9UhMGJ9E6XdFS21E1y7Hv5kjzvUGm",
      "proofValue": "z57X6vPoLKGWfTT8iCp7kD7eRNKuykcNYujbVrXeWqFe8WDc3GUBGvCxbdq5u6m4ZE7WNVM4zedxnVVzLozkcKWXE"
    }
  ]
]
```
Prettified version 2 of the DID (line 2 of v02_did.jsonl)

```json
[
  "2-QmSwrQpiTmTZrbJPF8q8viuqaZ1ZdxsU5um4zeZ8FbzEw9",
  "2025-02-27T13:44:33Z",
  {
    "witnessThreshold": 0
  },
  {
    "value": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
      "authentication": [
        "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
      ],
      "assertionMethod": [
        "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"
      ],
      "verificationMethod": [
        {
          "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
          "controller": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "auth-key-01",
            "x": "ngddzGFoi-yZDqasoBX8zvFO73rCHPCQcGVEiLVka3Y",
            "y": "v3x-KtZMZD7FZgT2dh-xwVriocHldTRKaijMvnwV4bQ"
          }
        },
        {
          "id": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
          "controller": "did:tdw:QmZnon39bXfMooTmyNzeqA7S7RS3btJPkfFHLoKxHaLreo:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
          "type": "JsonWebKey2020",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "kid": "assert-key-02",
            "x": "7d802vPuAZ-8SyEuTdfCE03-0YeHtrrO4DqcJPRJ8L4",
            "y": "pQsxkJETgGFaz3szf962_e1SMVTUAypKx-Fd7KPA3K4"
          }
        }
      ]
    }
  },
  [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-02-27T13:44:33Z",
      "verificationMethod": "did:key:z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8#z6MkuhNUavmMuQrh6rTKyGiGVc4WdKQW41kD12qaSmN5u4Z8",
      "proofPurpose": "authentication",
      "challenge": "2-QmSwrQpiTmTZrbJPF8q8viuqaZ1ZdxsU5um4zeZ8FbzEw9",
      "proofValue": "z5ZoqFzYDx2kPPTKAv6kjYAL3SpTqU4UFfRu9i4Xy1ioorGQAV5T3U7qAADe5EhjH3tdaWEpV7qGPQMaJF24vq6Qg"
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

### DID Update

Once a newly created `did.jsonl` file is available, you may use the `update` subcommand at any point to **completely**
replace the existing [verification material](https://www.w3.org/TR/did-core/#verification-material) in DID document:

```shell
java -jar didtoolbox.jar create \
    -u https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did18fa7c77-9dd1-4e20-a147-fb1bec146085/did.jsonl > /tmp/my-did.jsonl

# bear in mind, the command above will store the generated (auth/assert) keys in the .didtoolbox directory

java -jar didtoolbox.jar update \
    -d /tmp/did.jsonl \
    -a my-assert-key-01,.didtoolbox/assert-key-01.pub \
    -t my-auth-key-01,.didtoolbox/auth-key-01.pub \
    -s .didtoolbox/id_ed25519 \
    -v .didtoolbox/id_ed25519.pub > /tmp/did-2.jsonl
```

## Additional Information
- **Output Directory**: When creating new DIDs, the `.didtoolbox` directory is automatically created in the current working directory. Ensure you have the necessary permissions to create and write to this directory.
- **Multiple DIDs**: If you create multiple DIDs, please make sure to rename the `.didtoolbox` directory (or move/rename the files) after each creation run, since the key material will re-generated on each run and therefore overwritten.
- **Security**: Keep your private keys secure. Do not share them or expose them in unsecured environments.
- **Credentials file (e.g. in case of using Securosys Primus HSM):** Keep such files safely stored on the file system.
Alternatively, you may also fallback to a system user environment, instead.

## Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for contributing found in [CONTRIBUTING](./CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for details.
