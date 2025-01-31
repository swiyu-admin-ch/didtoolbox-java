# https://hub.docker.com/_/openjdk/tags?name=slim
# openjdk:23-slim is Debian GNU/Linux 12 (bookworm)
# CAUTION The platform MUST be appropriate for the libdidresolver.so shared library (as part of didresolver.jar).
#         Otherwise, when building image on a machine with arm64 CPU (e.g. on macOS M1/M2 ARM64 CPU), you should see
#         "WARNING: image platform (linux/amd64) does not match the expected platform (linux/arm64)"
FROM --platform=linux/amd64 openjdk:23-slim

MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar

ENTRYPOINT ["java","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
