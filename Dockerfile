# All Eclipse Temurin "jre-ubi10-minimal" base images are available here: https://hub.docker.com/_/eclipse-temurin/tags?name=jre-ubi10-minimal
FROM eclipse-temurin:25-jre-ubi10-minimal

RUN mkdir -p /didtoolbox
WORKDIR /didtoolbox

COPY target/didtoolbox-*-jar-with-dependencies.jar app.jar
COPY bin/entrypoint.sh entrypoint.sh
RUN chmod +x entrypoint.sh

# All image-specific envvars can easiliy be printed out by simply running:
#     podman inspect <IMAGE_NAME> --format='{{json .Config.Env}}' | jq -r '.[]|select(startswith("DIDTOOLBOX_"))'
ENV DIDTOOLBOX_BOOTCLASSPATH "./lib"
VOLUME ${DIDTOOLBOX_BOOTCLASSPATH}

ENTRYPOINT ["/didtoolbox/entrypoint.sh", "/didtoolbox/app.jar"]
