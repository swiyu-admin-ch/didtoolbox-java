# https://hub.docker.com/_/openjdk/tags?name=alpine
FROM openjdk:23
MAINTAINER vladica.stojic@bit.admin.ch

WORKDIR /usr/local/bin/didtoolbox
COPY target/didtoolbox-*-jar-with-dependencies.jar didtoolbox.jar

#ENV LD_LIBRARY_PATH /usr/java/openjdk-23/lib
#RUN ldconfig
#RUN env

#ENTRYPOINT ["java","-Djna.debug_load=true","-XshowSettings:properties","-Djava.io.tmpdir=/var/tmp","-Djna.tmpdir=/var/tmp","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
ENTRYPOINT ["java","-Djava.io.tmpdir=/var/tmp","-Djna.tmpdir=/var/tmp","-jar","/usr/local/bin/didtoolbox/didtoolbox.jar"]
