![swiyu GitHub banner](https://github.com/swiyu-admin-ch/swiyu-admin-ch.github.io/blob/main/assets/images/github-banner.jpg)

# DID-Toolbox

[![Pull Request Check](https://github.com/swiyu-admin-ch/didtoolbox-java/actions/workflows/pull-request-check.yml/badge.svg)](https://github.com/swiyu-admin-ch/didtoolbox-java/actions/workflows/pull-request-check.yml)

An official Swiss Government project made by
the [Federal Office of Information Technology, Systems and Telecommunication FOITT](https://www.bit.admin.ch/)
as part of the electronic identity (e-ID) project.

This project implements the DID-Toolbox, a helper utility for the purpose of creation, update or deactivation of DIDs
with respect to one of the following specifications:
* [Trust DID Web (`did:tdw`) - v0.3](https://identity.foundation/didwebvh/v0.3/) (optional)
* [DID Web + Verifiable History (`did:webvh`) - v1.0](https://identity.foundation/didwebvh/v1.0/) (default since v1.6.0)

## Table of contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [CLI Overview](#cli-overview)
- [Quickstart – Create Your First DID](#quickstart--create-your-first-did)
- [Update an existing DID](#update-an-existing-did)
- [Proof of Possession (PoP)](#proof-of-possession-pop)
  - [PoP Creation](#pop-creation)
  - [PoP Verification](#pop-verification)
- [Advanced Usage](#advanced-usage)
  - [Create](#did-creation)
  - [Update](#did-update)
  - [DID Deactivation (Revoke)](#did-deactivation-revoke)
  - [Key Rotation with Pre-Rotation](#key-rotation-with-pre-rotation)
- [The DID Toolbox (Java) API](#the-did-toolbox-java-api)
- [Additional Information](#additional-information)
- [Missing Features and Known Issues](#missing-features-and-known-issues)
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

- **Target Operating System:** Compatible with the following operating systems: Linux (x86-64 & aarch64), macOS (x86-64 & aarch64) and Windows (x86-64). Ensure your OS is up to date to avoid compatibility issues. <br>⚠️ **CAUTION** Beware of the target OS support when running the DID-Toolbox from within a Docker/Podman container. Due to [functional differences between musl and glibc](https://wiki.musl-libc.org/functional-differences-from-glibc.html), it is a known issue that [Alpine](https://hub.docker.com/_/alpine) images require workarounds. Luckily, ["Distroless"](https://github.com/GoogleContainerTools/distroless/tree/main/java) images offer pretty useful and viable alternative, as illustrated [here](examples/containerization/README.md).
- **Java Runtime Environment (JRE) 21 or Higher:** The DID-Toolbox requires Java JRE version 21 or above. Verify that Java is installed on your machine. [JNA](https://javadoc.io/doc/net.java.dev.jna/jna/latest/index.html) support is required, since the DID-Toolbox depends on another, platform dependent library, used to verify the generated DID log outputs.
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
    create      Create a DID and sign the initial DID log entry with the provided private key. To supply a signing/verifying key pair, always rely on 
            one of the three available command parameter sets exclusively, each of then denoting a whole another source of such key material: PEM 
            files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the required JCE 
            provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is by-convention expected to be stored on the system alongside the 
            DID-Toolbox in the lib subdirectory (e.g. as lib/primusX-java11.jar). Alternatively, you may also use 
            -Xbootclasspath/a:directories|zip|JAR-files option of the java command for the purpose
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
            A HTTP(S) DID URL (to did.jsonl) to create a DID log for
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
            Defines the DID method specification version to use when generating a DID log. Case-insensitive. Valid values: 'did:tdw:0.3', 
            'did:webvh:1.0' 
            Default: did:webvh:1.0
            Possible Values: [TDW_0_3, WEBVH_1_0]
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
            The ed25519 private key file required for signing a DID log entry or a PoP JWT. In PEM Format. This CLI parameter cannot be used in 
            conjunction with any of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.
          --verifying-key-files-next, -w
            One or more ed25519 public key file(s) to be used as 'pre-rotation' keys. In PEM format. Using the CLI option activates 'key 
            pre-rotation'. Analogously, deactivating 'key pre-rotation' goes simply by omitting this option altogether

    update      Update a DID log by replacing the existing verification material in DID document. To supply a signing/verifying key pair, always rely 
            on one of the three available command parameter sets exclusively, each of then denoting a whole another source of such key material: PEM 
            files, a Java KeyStore (PKCS12) or a Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the required JCE 
            provider (JAR) library (primusX-java8.jar or primusX-java11.jar) is by-convention expected to be stored on the system alongside the 
            DID-Toolbox in the lib subdirectory (e.g. as lib/primusX-java11.jar). Alternatively, you may also use 
            -Xbootclasspath/a:directories|zip|JAR-files option of the java command for the purpose
      Usage: update [options]

        Options:
          --assert, -a
            One or more assertion method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC P-256 
            public/verifying key
          --auth, -t
            One or more authentication method parameter(s) - each parameter consists of a (comma-separated) key name and a PEM file containing EC 
            P-256 public/verifying key
        * --did-log-file, -d
            The file containing a valid DID log to update
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
            The ed25519 private key file required for signing a DID log entry or a PoP JWT. In PEM Format. This CLI parameter cannot be used in 
            conjunction with any of --jks-* or --primus-* CLI parameters
          --verifying-key-files, -v
            One or more ed25519 public key file(s) for the DID Document’s verification method. In PEM format.
          --verifying-key-files-next, -w
            One or more ed25519 public key file(s) to be used as 'pre-rotation' keys. In PEM format. Using the CLI option activates 'key 
            pre-rotation'. Analogously, deactivating 'key pre-rotation' goes simply by omitting this option altogether

    deactivate      Deactivate (revoke) a DID log. To supply a signing/verifying key pair, always rely on one of the three available command 
            parameter sets exclusively, each of then denoting a whole another source of such key material: PEM files, a Java KeyStore (PKCS12) or a 
            Securosys Primus (HSM) connection. In case of a Securosys Primus (HSM) connection, the required JCE provider (JAR) library 
            (primusX-java8.jar or primusX-java11.jar) is by-convention expected to be stored on the system alongside the DID-Toolbox in the lib 
            subdirectory (e.g. as lib/primusX-java11.jar). Alternatively, you may also use -Xbootclasspath/a:directories|zip|JAR-files option of the 
            java command for the purpose
      Usage: deactivate [options]

        Options:
        * --did-log-file, -d
            The file containing a valid DID log to deactivate
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
            The ed25519 private key file required for signing a DID log entry or a PoP JWT. In PEM Format. This CLI parameter cannot be used in 
            conjunction with any of --jks-* or --primus-* CLI parameters

    create-pop      Create a proof of possession JWT signed with the provided private key that expires after 24 hours.
      Usage: create-pop [options]

        Options:
        * --did-log-file, -d
            The file containing a valid DID log to update
          --help, -h
            Display help for the DID toolbox command
        * --kid, -k
            KID of the key within the DID log to use.
        * --nonce, -n
            Possession which will be proven by the JWT
        * --signing-key-file, -s
            An EC P-256 private key file matching the specified key within the DID log

    verify-pop      Verifies the validity of the provided proof of possession JWT.
      Usage: verify-pop [options]

        Options:
        * --did-log-file, -d
            The file containing a valid DID log of the owner.
          --help, -h
            Display help for the DID toolbox command
        * --jwt, -j
            JWT to be verified
        * --nonce, -n
            Text representation of the possession to be included in the proof

$ java -jar didtoolbox.jar -V

didtoolbox 1.9.0
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
- **create**: Command to create a new DID (with `did:webvh:1.0` as default DID method since v1.6.0)
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
{"versionId":"1-QmUHs3qtWUdAX5cDWGET3cwEPWx1pbiMNRvZMM8niBYM5r","versionTime":"2025-09-16T08:28:33Z","parameters":{"method":"did:webvh:1.0","scid":"QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn","updateKeys":["z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"_yaER4Zd_knfeAvNEbbLSU6EYXQmmwyUPd3_Ow03XWM","y":"Qg24PtsFEjubwIaPllkiD53fp9P5KlkWykA-yH3zWHc","kid":"auth-key-01"}},{"id":"did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"oj9V39ywyS7kcRd1ByhTjHbr_VJm1VYa6yXM67d_IDk","y":"bRX0IrfBBhZ9Y0k9QNgRYRCjT8NK5KmsozXP1usxesI","kid":"assert-key-01"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-09-16T08:28:33Z","verificationMethod":"did:key:z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh#z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh","proofPurpose":"assertionMethod","proofValue":"z5CHhr58M9wbzN3MaXzaCWskPtyXe2GiCWTFA2s2fEapPVqLjH5DLJqN3rwDqyvp67CQyKjkP58sVANHEmR6DTha5"}]}
```

Prettified version of the DID log content above.

```json
{
  "versionId": "1-QmUHs3qtWUdAX5cDWGET3cwEPWx1pbiMNRvZMM8niBYM5r",
  "versionTime": "2025-09-16T08:28:33Z",
  "parameters": {
    "method": "did:webvh:1.0",
    "scid": "QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn",
    "updateKeys": [
      "z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh"
    ],
    "portable": false
  },
  "state": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1"
    ],
    "id": "did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
    "authentication": [
      "did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
    ],
    "assertionMethod": [
      "did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
    ],
    "verificationMethod": [
      {
        "id": "did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "_yaER4Zd_knfeAvNEbbLSU6EYXQmmwyUPd3_Ow03XWM",
          "y": "Qg24PtsFEjubwIaPllkiD53fp9P5KlkWykA-yH3zWHc",
          "kid": "auth-key-01"
        }
      },
      {
        "id": "did:webvh:QmW3H4phgD2bKKWb1GcmtNbFhxVD3bonRLmsf9XdMrUnzn:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "oj9V39ywyS7kcRd1ByhTjHbr_VJm1VYa6yXM67d_IDk",
          "y": "bRX0IrfBBhZ9Y0k9QNgRYRCjT8NK5KmsozXP1usxesI",
          "kid": "assert-key-01"
        }
      }
    ]
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-09-16T08:28:33Z",
      "verificationMethod": "did:key:z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh#z6Mku4WkTingBAr4jNDUVfavPWghiFQztsBGJXox5kjj7Lhh",
      "proofPurpose": "assertionMethod",
      "proofValue": "z5CHhr58M9wbzN3MaXzaCWskPtyXe2GiCWTFA2s2fEapPVqLjH5DLJqN3rwDqyvp67CQyKjkP58sVANHEmR6DTha5"
    }
  ]
}
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
{"versionId":"1-QmczXqfpHo3bn7Et1CbHRX6XpAvtqvCHbWsrciEpntf3WS","versionTime":"2025-09-16T08:33:55Z","parameters":{"method":"did:webvh:1.0","scid":"QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg","updateKeys":["z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h"],"portable":false},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"hmIMtNewEglkDSsVNmQPmkwLKLmZ97Gygoy7fmqlySc","y":"G_Bi6AtN8QfJ0P3K0AMsNiLZMacUNjBFD_BDyOG0uNQ","kid":"auth-key-01"}},{"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"ge1bBnzmdDtOCv5OXQrnYvudMryuro8VaIOoV4pmTmw","y":"Y8fl9USMdlDYZeP_eH9o1z5rnJqe2QKezX4locUf2es","kid":"assert-key-01"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-09-16T08:33:55Z","verificationMethod":"did:key:z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h#z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h","proofPurpose":"assertionMethod","proofValue":"ziGJYAVvWUdevzJBrpeZG97E56bu5Tk3pyN78CymGS3Ttf6a1GdHmC3TPzNNY2CtAttcBZ5WxoNyggMnyMWb8Lm8"}]}
{"versionId":"2-QmeqibtMt2LoSW1uvTLJ22pUbRsnM2UPPo2TAm9PDXnbhB","versionTime":"2025-09-16T08:34:24Z","parameters":{},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085","authentication":["did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"],"assertionMethod":["did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"],"verificationMethod":[{"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"auth-key-01","x":"ge1bBnzmdDtOCv5OXQrnYvudMryuro8VaIOoV4pmTmw","y":"Y8fl9USMdlDYZeP_eH9o1z5rnJqe2QKezX4locUf2es"}},{"id":"did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert-key-02","x":"olUnQEfh8IgyUhqrs6ILzZlwPsxV-aJpeOZQyxvV0mk","y":"ndiqwn8wHB2ewgVk5TqpQZu2IiGO0ZylLoHl4M9Otco"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-09-16T08:34:24Z","verificationMethod":"did:key:z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h#z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h","proofPurpose":"assertionMethod","proofValue":"z41PJxWHXsPP5bc5VEReki9voZYiou2wKh9iFq7RbD2eqv6Xy7GSWPbgNp77XbKLQhLxAfq2A1dV2nmFTae7R11Tb"}]}
```

Prettified initial version (version 1) of the created DID (line #1 of v02_did.jsonl)

```json
{
  "versionId": "1-QmczXqfpHo3bn7Et1CbHRX6XpAvtqvCHbWsrciEpntf3WS",
  "versionTime": "2025-09-16T08:33:55Z",
  "parameters": {
    "method": "did:webvh:1.0",
    "scid": "QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg",
    "updateKeys": [
      "z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h"
    ],
    "portable": false
  },
  "state": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1"
    ],
    "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
    "authentication": [
      "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
    ],
    "assertionMethod": [
      "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01"
    ],
    "verificationMethod": [
      {
        "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "hmIMtNewEglkDSsVNmQPmkwLKLmZ97Gygoy7fmqlySc",
          "y": "G_Bi6AtN8QfJ0P3K0AMsNiLZMacUNjBFD_BDyOG0uNQ",
          "kid": "auth-key-01"
        }
      },
      {
        "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-01",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "x": "ge1bBnzmdDtOCv5OXQrnYvudMryuro8VaIOoV4pmTmw",
          "y": "Y8fl9USMdlDYZeP_eH9o1z5rnJqe2QKezX4locUf2es",
          "kid": "assert-key-01"
        }
      }
    ]
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-09-16T08:33:55Z",
      "verificationMethod": "did:key:z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h#z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h",
      "proofPurpose": "assertionMethod",
      "proofValue": "ziGJYAVvWUdevzJBrpeZG97E56bu5Tk3pyN78CymGS3Ttf6a1GdHmC3TPzNNY2CtAttcBZ5WxoNyggMnyMWb8Lm8"
    }
  ]
}
```

Prettified version 2 of the DID (line #2 of v02_did.jsonl)

```json
{
  "versionId": "2-QmeqibtMt2LoSW1uvTLJ22pUbRsnM2UPPo2TAm9PDXnbhB",
  "versionTime": "2025-09-16T08:34:24Z",
  "parameters": {},
  "state": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1"
    ],
    "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085",
    "authentication": [
      "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01"
    ],
    "assertionMethod": [
      "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02"
    ],
    "verificationMethod": [
      {
        "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#auth-key-01",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "kid": "auth-key-01",
          "x": "ge1bBnzmdDtOCv5OXQrnYvudMryuro8VaIOoV4pmTmw",
          "y": "Y8fl9USMdlDYZeP_eH9o1z5rnJqe2QKezX4locUf2es"
        }
      },
      {
        "id": "did:webvh:QmacfmG8oFVFpKheaFMgKXyWpL163m9JUD5Zd2yi8UY8hg:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:18fa7c77-9dd1-4e20-a147-fb1bec146085#assert-key-02",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256",
          "kid": "assert-key-02",
          "x": "olUnQEfh8IgyUhqrs6ILzZlwPsxV-aJpeOZQyxvV0mk",
          "y": "ndiqwn8wHB2ewgVk5TqpQZu2IiGO0ZylLoHl4M9Otco"
        }
      }
    ]
  },
  "proof": [
    {
      "type": "DataIntegrityProof",
      "cryptosuite": "eddsa-jcs-2022",
      "created": "2025-09-16T08:34:24Z",
      "verificationMethod": "did:key:z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h#z6MkjWDPEwWPrvvtrcUvtAvYSF5ovuHvqaA493uuPPdGGS4h",
      "proofPurpose": "assertionMethod",
      "proofValue": "z41PJxWHXsPP5bc5VEReki9voZYiou2wKh9iFq7RbD2eqv6Xy7GSWPbgNp77XbKLQhLxAfq2A1dV2nmFTae7R11Tb"
    }
  ]
}
```

## Proof of Possession (PoP)

The DID-Toolbox also offers various other options not closely related to DID. One of those is possibility to generate
a [Proof-of-Possession (PoP)](https://www.rfc-editor.org/rfc/rfc7800.html) using the very same Ed25519 signing/verifying key pair used while creating/updating DID logs.

A PoP is nothing but a [JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519), signed cryptographically to ensure authenticity -
such JWT can declare that the _presenter_ of the JWT possesses a particular proof-of-possession (PoP) key.
In addition, the _recipient_ would consequently be able to cryptographically confirm proof of possession of the key 
by the _presenter_. Being able to prove possession of a key is also sometimes described as the _presenter_ being a _holder-of-key_.

### PoP Creation

To create a PoP using the DID-Toolbox, the very same Ed25519 signing key used for DID creation/update is required, alongside a 
_possession_ ([nonce](https://datatracker.ietf.org/doc/html/rfc7800#section-3.6)), as illustrated by the following script:

```shell
# Create quickstart to generate an initial DID log with an assertion key pair
java -jar didtoolbox.jar create -u https://example.com -f > did.jsonl

# Export kid of the assertion key within the generated DID log.
export KID=$(jq -r ".state.assertionMethod[0]" did.jsonl)

# Create proof of possession JWT and store it for later
java -jar didtoolbox.jar create-pop -d did.jsonl -k ${KID} -s .didtoolbox/assert-key-01 -n "Your Nonce" > jwt
```

The result is valid JWT token that looks like this:

```
eyJraWQiOiJkaWQ6a2V5Ono2TWt0ZEFyM2lVUmVVN0hzQ2Y3Sm5vQ2pRNXVycEtUeFpTQzQ5S25qRVZzQTVDQSN6Nk1rdGRBcjNpVVJlVTdIc0NmN0pub0NqUTV1cnBLVHhaU0M0OUtuakVWc0E1Q0EiLCJhbGciOiJFZDI1NTE5In0.eyJleHAiOjE3NTM4NjUyNjcsIm5vbmNlIjoiWW91ciBOb25jZSJ9.Kn5o175IDYBjR8Vw_DId5DkaScildD9sVFg7ear9ujAfYQCsxGbqlaNTO2leg-NA9mDY5q_07YbodcJvhaGADQ
```

To decode the information contained within such JWT, the [JWT.io](https://www.jwt.io/) can be used:

```json lines
{
  "kid": "did:webvh:QmfNchmAvY4EJ7WrxaiWRyrspV9B8dSRzUgcs4CWUggiBD:example.com#assert-key-01",
  "alg": "ES256"
}
{
  "iss": "did:webvh:QmfNchmAvY4EJ7WrxaiWRyrspV9B8dSRzUgcs4CWUggiBD:example.com",
  "exp": 1772109310,
  "nonce": "Your Nonce",
  "iat": 1772022910
}
```

Basically, any PoP JWT features quite a few (header/payload) claims, all of them being essential in the process of PoP verification.  

### PoP Verification

A proof of possession can claim ownership over anything. For it to matter it first needs to be verified. 

```shell
# Create quickstart to generate an initial DID log along the required signing/verifying key pair and jwt
java -jar didtoolbox.jar create -u https://example.com -f > did.jsonl
export KID=$(jq -r ".state.assertionMethod[0]" did.jsonl)
java -jar didtoolbox.jar create-pop -d did.jsonl -k ${KID} -s .didtoolbox/assert-key-01 -n "Your Nonce" > jwt

# verify created proof
java -jar didtoolbox.jar verify-pop -d did.jsonl -n "Your Nonce" -j $(cat jwt)
# the previous command should produce an output like:
# Provided JWT is valid.
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
    -d /tmp/my-did.jsonl \
    -s .didtoolbox/id_ed25519 > /tmp/my-did-deactivated.jsonl
```

The _deactivated_ DID log file should now contain another DID log entry denoting deactivation (via DID parameter `{"deactivated":true}`) and featuring no key material whatsoever: 

```json
{"versionId":"2-QmQ789n4M1GJNmqJrZc5mh31A6qTWQhGvXBswThav1cEoS","versionTime":"2025-09-16T08:38:57Z","parameters":{"deactivated":true,"updateKeys":[]},"state":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],"id":"did:webvh:QmawSKWDN3LNMMokezM1jwGFeZzroSnuayx4mGmS7WTtiP:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did18fa7c77-9dd1-4e20-a147-fb1bec146085"},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2025-09-16T08:38:57Z","verificationMethod":"did:key:z6Mkr4vcVTZGzinKrfRQisUAa79rCSFrBG5qzf2QatPaZ9Ag#z6Mkr4vcVTZGzinKrfRQisUAa79rCSFrBG5qzf2QatPaZ9Ag","proofPurpose":"assertionMethod","proofValue":"z67KCC9BQzLebaJYQZgNbyKLrGZf7Hpt1Th8pXUTbaFRiJj2nBFwNEqiUadXxpAVw2My9GZp2EhDhKH67PHgHaA6Y"}]}
```

### Key Rotation with Pre-Rotation

The DID Toolbox also supports a [_post-quantum safe_](https://didwebvh.info/latest/implementers-guide/prerotation-keys/#post-quantum-attacks)
technique called [Key Rotation with Pre-Rotation](https://didwebvh.info/latest/implementers-guide/prerotation-keys).
Here is a short script illustrating it:

```shell
# optionally, get the latest version of DID Toolbox (replace <VERSION> with any of available versions released after 1.6.0)
# wget https://repo1.maven.org/maven2/io/github/swiyu-admin-ch/didtoolbox/<VERSION>/didtoolbox-<VERSION>-jar-with-dependencies.jar -O didtoolbox.jar
alias didtoolbox='java -jar didtoolbox.jar'

# generate couple of pre-rotation keys
rm -fr .didtoolbox*
for i in {1..5}; do didtoolbox create -f -m did:webvh:1.0 -u https://domain.com/path1/path2 &> /dev/null; mv .didtoolbox .didtoolbox$(printf "%03d" $((i))); done

# initial DID log with a key to be used for pre-rotation 
didtoolbox create -f -m did:webvh:1.0 \
    -u https://domain.com/path1/path2 \
    -w .didtoolbox001/id_ed25519.pub > did001.jsonl

# add more DID log entries featuring previously generated pre-rotation keys
for i in {1..5}; do didtoolbox update \
    -d did$(printf "%03d" $((i))).jsonl \
    -a my-assert-key-01,.didtoolbox/assert-key-01.pub \
    -t my-auth-key-01,.didtoolbox/auth-key-01.pub \
    -s .didtoolbox$(printf "%03d" $((i)))/id_ed25519 \
    -v .didtoolbox$(printf "%03d" $((i)))/id_ed25519.pub \
    -w .didtoolbox$(printf "%03d" $((i+1)))/id_ed25519.pub > did$(printf "%03d" $((i+1))).jsonl; done

# checkpoint (print only the pre-rotation keys inside the DID log)
cat did005.jsonl | jq -c '.|.parameters'

# the command above should produce the following output:
#
# {"method":"did:webvh:1.0","scid":"QmPQ6QpZ34T2FUN4Qoav4w1UXqRHPEr74Ecthu8Ve1ek3r","updateKeys":["z6MktAwYMZ2DPFwNP9JpJYvZg7DGvUc3rQqoPWVRai8ujUkC"],"nextKeyHashes":["Qmcv4wvjmDbowp6ziKanyEnNxwfRGf8gQ7UZXAmAgwSXg2"],"portable":false}
# {"nextKeyHashes":["QmXa2irGDLZP2WFiQCSAmuRWpCQVKbKb3NwgUB3EUwFef1"],"updateKeys":["z6MkowukYWPGu3y8pVTskco8ziTMnS4U7tVPKkWv1fAd4XS5"]}
# {"nextKeyHashes":["QmaiT2EVB9WZcYae9QS94agPhE5isd96xGe8TMyjbRcinm"],"updateKeys":["z6Mki8rv7cMRZ5jiLtGgfbuRvknwfUZbJFjE8SApikXixvVv"]}
# {"nextKeyHashes":["QmZbAEQCaBLYxWz6eWMQas8nfKa3vXhRoMVQD2o35RDZm2"],"updateKeys":["z6Mko41raveKqxPg5gUzv2g7Gk9a9rmCNXNn5MCKsQECFQ5E"]}
# {"nextKeyHashes":["QmPjawyNkfnZqNomHMct8zE1QHiqfPPUGfbYyerNuXRxXo"],"updateKeys":["z6MkkPDkNqJ2CmVB89gPyJNhC5GJ2PfiPqtLsWvMHUyHS1L5"]}
```

## The DID Toolbox (Java) API

The sole bedrock of DID Toolbox (Java) API are the classes residing in the `ch.admin.bj.swiyu.didtoolbox.context` package:
* [DidLogCreatorContext](src/main/java/ch/admin/bj/swiyu/didtoolbox/context/DidLogCreatorContext.java)
* [DidLogUpdaterContext](src/main/java/ch/admin/bj/swiyu/didtoolbox/context/DidLogUpdaterContext.java)
* [DidLogDeactivatorContext](src/main/java/ch/admin/bj/swiyu/didtoolbox/context/DidLogDeactivatorContext.java)

![didtoolbox-classes-only](src/main/plantuml/didtoolbox-api-classes-only.svg)

Each of these complementary classes are in charge of DID log manipulation in specification-agnostic fashion
i.e. regardless of DID method specification, whereas currently supported are only `did:tdw:0.3` (legacy) and `did:webvh:1.0` (final).
By relying fully on the [Builder (creational) Design Pattern](https://en.wikipedia.org/wiki/Builder_pattern), thus making heavy use of
[fluent design](https://en.wikipedia.org/wiki/Fluent_interface), these classes are intended to be instantiated exclusively
via their static `builder()` methods. The relevant Java documentation also feature some typical usage examples.

For further details, please see the relevant [PlantUML diagrams](src/main/plantuml/README.md).

To [configure Apache Maven](https://central.sonatype.org/consume/consume-apache-maven/) to consume a published package from
[Maven Central Repository](https://repo1.maven.org/maven2/ch/admin/swiyu/didtoolbox),
edit your `pom.xml` file to include the following entry to `dependencies` section:

```xml
<dependency>
    <groupId>ch.admin.swiyu</groupId>
    <artifactId>didtoolbox</artifactId>
    <!--version>[ANY_AVAILABLE_VERSION]</version-->
</dependency>
```

To [configure Gradle](https://central.sonatype.org/consume/consume-gradle/) to consume a published package from
[Maven Central Repository](https://repo1.maven.org/maven2/ch/admin/swiyu/didtoolbox),
add the following entry to `dependencies` section in your `build.gradle.kts` (Kotlin DSL) file:

```kotlin
implementation("ch.admin.swiyu:didtoolbox:[ANY_AVAILABLE_VERSION]")
```

Various indicative code examples of using the (Java) API are available in the [examples](examples) directory.

## Additional Information
- **Output Directory**: When creating new DIDs, the `.didtoolbox` directory is automatically created in the current working directory. Ensure you have the necessary permissions to create and write to this directory.
- **Multiple DIDs**: If you create multiple DIDs, please make sure to rename the `.didtoolbox` directory (or move/rename the files) after each creation run. The DID-Toolbox will prevent you from overwriting existing key pairs by accident and abort with an error.
- **Security**: Keep your private keys secure. Do not share them or expose them in unsecured environments.
- **Credentials file (e.g. in case of using Securosys Primus HSM):** Keep such files safely stored on the file system.
Alternatively, you may also fall back to a system user environment, instead.

## Missing Features and Known Issues

The swiyu Public Beta Trust Infrastructure was deliberately released at an early stage to enable future ecosystem participants. The [feature roadmap](https://github.com/orgs/swiyu-admin-ch/projects/1/views/7) shows the current discrepancies between Public Beta and the targeted productive Trust Infrastructure. There may still be minor bugs or security vulnerabilities in the test system. These are marked as [‘KnownIssues’](https://github.com/swiyu-admin-ch/didtoolbox-java/issues) in each repository.

## Contributions and feedback

We welcome any feedback on the code regarding both the implementation and security aspects. Please follow the guidelines for contributing found in [CONTRIBUTING](./CONTRIBUTING.md).

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](LICENSE) file for details.
