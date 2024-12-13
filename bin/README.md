# bin scripts

This directory contains [`podman`](https://docs.podman.io/en/latest/)-based Shell scripts required when running the DID toolbox as Podman image.

Assuming the `mvn package` has already been executed, to create a Podman image featuring the DID toolbox, if not created already, please run: 
```shell
./podman-build.sh
```

So, running the `podman image ls` command right after should result in at least two entries:
```text
REPOSITORY                            TAG         IMAGE ID      CREATED         SIZE
localhost/e-id-admin/didtoolbox-java  latest      afb7d10ad258  15 minutes ago  607 MB
docker.io/library/openjdk             23          b37c977c525b  3 months ago    598 MB
```

Finally, once you have the image in your local repo, to run the DID toolbox (as Podman image), please use `didtoolbox.sh`, e.g.:
```shell
./didtoolbox.sh create \
  -a myAssertionKey1,src/test/data/public.pem \
  -a myAssertionKey2,src/test/data/public.pem \
  -d domain.com -p path \
  -j src/test/data/mykeystore.jks \
  --jks-password changeit \
  --jks-alias myalias \
  -s src/test/data/private.pem \
  -v src/test/data/public.pem                                                  
```
