#!/usr/bin/env bash

#
# https://docs.oracle.com/en/java/javase/24/docs/specs/man/java.html#extra-options-for-java:
#
# -Xbootclasspath/a:directories|zip|JAR-files
#    Specifies a list of directories, JAR files, and ZIP archives to append to the end of the default bootstrap class path.
#
#    On Windows, semicolons (;) separate entities in this list; on other platforms it is a colon (:).
#
test -d "${DIDTOOLBOX_BOOTCLASSPATH}" && bootclasspath_java_opt=-Xbootclasspath/a:$(find "${DIDTOOLBOX_BOOTCLASSPATH}" -type f -name "*.jar" | xargs -I {} echo {} | tr '\n' ':')

java ${bootclasspath_java_opt} -jar "$@"