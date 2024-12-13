package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.jar.Manifest;

public class Main {

    @Parameter(names = {"--help", "-h"},
            description = "Display help for the DID toolbox",
            help = true)
    boolean help;

    @Parameter(names = {"--version", "-V"},
            description = "Display version")
    boolean version;

    private static String getManifestResourceValue(String name) {
        try {
            return new Manifest(Objects.requireNonNull(Main.class.getClassLoader().getResource("META-INF/MANIFEST.MF")).openStream()).getMainAttributes().getValue(name);
        } catch (IOException ignore) {
            //
        }
        return "undefined";
    }

    private String getImplementationTitle() {
        // CAUTION Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return getManifestResourceValue("Implementation-Title");
    }

    private String getImplementationVersion() {
        // CAUTION Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return getManifestResourceValue("Implementation-Version");
    }

    private String getImplementationVersionX() {
        try {
            Manifest manifest = new Manifest(Objects.requireNonNull(this.getClass().getClassLoader().getResource("META-INF/MANIFEST.MF")).openStream());
            // CAUTION Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
            return manifest.getMainAttributes().getValue("Implementation-Version");
        } catch (IOException ignore) {
            //
        }
        return "undefined";
    }

    public static void main(String... args) {

        var main = new Main();

        var createCommand = new CreateTdwCommand();
        var jc = JCommander.newBuilder()
                .addObject(main)
                .addCommand("create", createCommand)
                .programName(main.getImplementationTitle())
                .columnSize(150)
                .build();

        var usageFormatter = new UnixStyleUsageFormatter(jc);
        jc.setUsageFormatter(usageFormatter);

        try {
            jc.parse(args);
        } catch (ParameterException e) {
            System.err.println(e.getLocalizedMessage());
            jc.usage();
            System.exit(1);
        }

        if (main.version) {
            System.out.println(main.getImplementationTitle() + " " + main.getImplementationVersion());
            System.exit(0);
        }

        if (main.help) {
            jc.usage();
            System.exit(0);
        }

        var parsedCmdStr = jc.getParsedCommand();
        if (parsedCmdStr == null) {
            jc.usage();
            System.exit(1);
        }

        switch (parsedCmdStr) {

            case "create":

                if (createCommand.help) {
                    jc.usage(parsedCmdStr);
                    System.exit(0);
                }

                var domain = createCommand.domain;
                var path = createCommand.path;

                var assertions = createCommand.assertions;
                Map<String, AssertionMethodInput> assertionMethodsMap = new HashMap<>();
                for (CreateTdwCommand.AssertionMethodParameters param : assertions) {
                    assertionMethodsMap.put(param.key, new AssertionMethodInput(param.publicKeyMultibase));
                }

                var signingKeyPemFile = createCommand.signingKeyPemFile;
                var verifyingKeyPemFile = createCommand.verifyingKeyPemFile;

                var jksFile = createCommand.jksFile;
                var jksPassword = createCommand.jksPassword;
                var jksAlias = createCommand.jksAlias;

                String didLogEntry = null;
                try {

                    Signer signer = null;
                    if (signingKeyPemFile != null && verifyingKeyPemFile != null) {
                        signer = new Signer(signingKeyPemFile, verifyingKeyPemFile);
                    } else if (jksFile != null && jksPassword != null && jksAlias != null) {
                        signer = new Signer(new FileInputStream(jksFile), jksPassword, jksAlias);
                    }

                    if (signer == null) {
                        System.err.println("Source for the (signing/verifying) keys undefined. Use one of the relevant options to supply keys");
                        jc.usage();
                        System.exit(1);
                    }

                    didLogEntry = TdwCreator.builder()
                            .signer(signer)
                            .assertionMethods(assertionMethodsMap)
                            .build()
                            .create(domain, path);

                } catch (Exception e) {
                    System.err.println("Command '" + parsedCmdStr + "' failed due to: " + e.getLocalizedMessage());
                    System.exit(1);
                }

                System.out.println(didLogEntry);

                break;

            default:
                System.err.println("Invalid command: " + parsedCmdStr);
                jc.usage();
                System.exit(1);
        }

        System.exit(0);
    }
}