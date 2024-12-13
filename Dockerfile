# https://hub.docker.com/_/openjdk/tags?name=alpine
FROM openjdk:23
MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar
ENTRYPOINT ["java","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
