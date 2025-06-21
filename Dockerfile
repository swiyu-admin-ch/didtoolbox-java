# All OpenJDK "slim" base images are available here: https://hub.docker.com/_/openjdk/tags?name=slim
# E.g. the openjdk:26-slim has Debian GNU/Linux 12 (bookworm) as foundation.
# However, beware that using Bullseye-based images on MacOS may result in:
# "java.lang.UnsatisfiedLinkError: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /root/.cache/JNA/temp/jna18326432266987702332.tmp)"
FROM --platform=linux/arm64 openjdk:26-slim

MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar
# CAUTION Securosys Primus JCE security provider libraries ("Securosys JCE provider for Securosys Primus HSM")
#         should NOT be distributed this way. However, for testing purposes only, you may try uncommenting one of the subsequent two lines:
#COPY lib/primusX-java11.jar lib/primusX-java11.jar
#COPY lib/primusX-java8.jar  lib/primusX-java8.jar

ENTRYPOINT ["java","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
