# https://hub.docker.com/_/openjdk/tags?name=slim
# openjdk:23-slim is Debian GNU/Linux 12 (bookworm)
# CAUTION The platform MUST be appropriate for the libdidresolver.so shared library (as part of didresolver.jar).
#FROM --platform=linux/amd64 openjdk:23-slim
FROM --platform=linux/arm64/v8 openjdk:23-slim

MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar

ENTRYPOINT ["java","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
