FROM alpine/curl AS curl

# All version are avilable here: https://central.sonatype.com/artifact/ch.admin.swiyu/didtoolbox/versions
ARG VERSION="1.8.0"

WORKDIR /app
RUN curl --fail --output /app/app.jar \
    "https://repo1.maven.org/maven2/ch/admin/swiyu/didtoolbox/$VERSION/didtoolbox-$VERSION-jar-with-dependencies.jar"

# See https://github.com/GoogleContainerTools/distroless/blob/main/java
FROM gcr.io/distroless/java21-debian12
WORKDIR /app
COPY --from=curl /app ./

# Accept timezone as a build argument with a default
ARG TZ="Europe/Zurich"
ENV TZ=${TZ}

# CAUTION The entrypoint of this image is set to the equivalent of "java -jar",
#         so this image expects users to supply a path to a JAR file in the CMD ["/app/app.jar"].
#         However, additional CLI options can be supplied only via ENTRYPOINT
ENTRYPOINT ["java", "-jar", "/app/app.jar"]

# To be able to use HSM keys (e.g. Securosys Primus HSM),
# the relevant [Securosys Primus libraries](https://docs.securosys.com/jce/Downloads/) are required.
# For the purpose of referencing them on the file system,
# the following [extra option for java](https://docs.oracle.com/en/java/javase/24/docs/specs/man/java.html#extra-options-for-java) is available e.g.
#
# -Xbootclasspath/a:directories|zip|JAR-files
#    Specifies a list of directories, JAR files, and ZIP archives to append to the end of the default bootstrap class path.
#
#    On Windows, semicolons (;) separate entities in this list; on other platforms it is a colon (:).
#
# For instance, assuming the Primus libs are stored in the lib directory, the ENTRYPOINT should be extended the following way:
# ENTRYPOINT ["java", "-Xbootclasspath/a:lib/primusX-java8.jar:lib/primusX-java11.jar", "-jar", "/app/app.jar"]