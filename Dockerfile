# All OpenJDK "slim" base images are available here: https://hub.docker.com/_/openjdk/tags?name=slim
# E.g. the openjdk:26-slim has Debian GNU/Linux 12 (bookworm) as foundation.
# However, beware that using Bullseye-based images on MacOS may result in:
# "java.lang.UnsatisfiedLinkError: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /root/.cache/JNA/temp/jna18326432266987702332.tmp)"
FROM --platform=linux/arm64 openjdk:26-slim

MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar
COPY bin/entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/usr/local/bin/didtoolbox/entrypoint.sh"]
