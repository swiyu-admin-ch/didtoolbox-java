# https://hub.docker.com/_/openjdk/tags?name=slim
# openjdk:23-slim is Debian GNU/Linux 12 (bookworm)
# CAUTION The platform MUST be appropriate for the libdidresolver.so shared library (as part of didresolver.jar).
FROM --platform=linux/arm64 openjdk:21-slim
#FROM --platform=linux/arm64 openjdk:21-bookworm
#FROM --platform=linux/arm64 openjdk:21-slim-bookworm
#FROM --platform=linux/arm64 gradle:jdk21-alpine
#FROM --platform=linux/arm64 gradle:jdk21-ubi-minimal

# CAUTION Beware that using either:
#FROM --platform=linux/arm64    openjdk:21-bullseye
# or
#FROM --platform=linux/arm64    openjdk:21-buster
# will end up with "java.lang.UnsatisfiedLinkError: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.33' not found (required by /root/.cache/JNA/temp/jna18326432266987702332.tmp)"

# Beware that using either (whereas openjdk:19-alpine is pretty (three years) old):
#FROM openjdk:19-alpine
# or
#FROM --platform=linux/arm64 alpine/java:21-jdk
# would end up with "Error: initializing source docker://swiyu-admin-ch/didtoolbox-java:latest: reading manifest latest in docker.io/swiyu-admin-ch/didtoolbox-java: requested access to the resource is denied"

MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar
# CAUTION Securosys Primus JCE security provider libraries ("Securosys JCE provider for Securosys Primus HSM")
#         should NOT be distributed this way. However, for testing purposes only, you may try uncommenting one of the subsequent two lines:
#COPY lib/primusX-java11.jar lib/primusX-java11.jar
#COPY lib/primusX-java8.jar  lib/primusX-java8.jar

ENTRYPOINT ["java","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
