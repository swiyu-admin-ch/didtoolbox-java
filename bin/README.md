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
          --assertion, -a
            An (embedded) assertion method (comma-separated) parameters: a key name as well as a PEM file containing Ed25519 public/verifying key, as 
            defined by DIDs v1.0 (https://www.w3.org/TR/did-core/#assertion)
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

This repo already contains some keys intended for testing purposes, so feel free to try out the following example: 

```shell
./bin/didtoolbox.sh create \
    -a myAssertionKey1,src/test/data/public.pem \
    -a myAssertionKey2,src/test/data/public.pem \
    -d https://domain.com:443 \
    -p path1/path2 \
    -j src/test/data/mykeystore.jks \
    --jks-password changeit \
    --jks-alias    myalias \
    -s src/test/data/private.pem \
    -v src/test/data/public.pem                                              
```
