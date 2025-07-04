package ch.admin.bj.swiyu.didtoolbox;

import java.io.IOException;
import java.util.Arrays;
import java.util.jar.Manifest;

/**
 * A neat helper providing access to the local <a href="https://docs.oracle.com/javase/tutorial/deployment/jar/manifestindex.html">JAR manifest</a> entries and attributes.
 * <p>
 * HINT To ensure a proper JAR manifest is created automatically, you may make use of the {@code maven-assembly-plugin} -
 * more specifically, of the relevance here are both
 * <a href="https://maven.apache.org/shared/maven-archiver/index.html#class_manifest">manifest</a> and
 * <a href="https://maven.apache.org/shared/maven-archiver/index.html#class_manifestSection">manifestEntries</a> section.
 */
class ManifestUtils {
    private ManifestUtils() {
    }

    private static String getManifestMainAttributeValue(String name) {
        try {
            var iter = Main.class.getClassLoader().getResources("META-INF/MANIFEST.MF").asIterator();
            while (iter.hasNext()) {
                var elem = iter.next();
                var manifest = new Manifest(elem.openStream()); // may also throw java.io.IOException
                var mainClassAttr = manifest.getMainAttributes().getValue("Main-Class");
                // match it to local the JAR, as there might also be some others out there, like Securosys Primus libs
                if (mainClassAttr != null && mainClassAttr.equals(Main.class.getName())) {
                    return manifest.getMainAttributes().getValue(name);
                }
            }
        } catch (IOException e) {
            //
        }

        return "undefined";
    }

    static String getImplementationTitle() {
        // HINT Simply ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return Arrays.stream(getManifestMainAttributeValue("Implementation-Title").split(":")).toList().getLast();
    }

    static String getImplementationVersion() {
        // HINT Simply Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return getManifestMainAttributeValue("Implementation-Version");
    }
}
