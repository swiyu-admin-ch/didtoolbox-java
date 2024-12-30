package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.io.File;
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
            overAndOut(jc, e.getLocalizedMessage());
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

                Map<String, String> assertionMethodsMap = new HashMap<>();
                var assertionMethodKeys = createCommand.assertionMethodKeys;
                if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {
                    for (CreateTdwCommand.VerificationMethodParameters param : assertionMethodKeys) {
                        assertionMethodsMap.put(param.key, param.jwk);
                    }
                }

                Map<String, String> authMap = new HashMap<>();
                var authenticationKeys = createCommand.authenticationKeys;
                if (authenticationKeys != null && !authenticationKeys.isEmpty()) {
                    for (CreateTdwCommand.VerificationMethodParameters param : authenticationKeys) {
                        authMap.put(param.key, param.jwk);
                    }
                }

                File signingKeyPemFile = createCommand.signingKeyPemFile;
                File verifyingKeyPemFile = createCommand.verifyingKeyPemFile;

                File jksFile = createCommand.jksFile;
                String jksPassword = createCommand.jksPassword;
                String jksAlias = createCommand.jksAlias;

                if (signingKeyPemFile != null && verifyingKeyPemFile != null &&
                        jksFile != null && jksPassword != null && jksAlias != null) {
                    overAndOut(jc, "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
                }

                String didLogEntry = null;
                try {

                    Ed25519SignerVerifier signer = new Ed25519SignerVerifier(); // default with generated key pair
                    if (signingKeyPemFile != null && verifyingKeyPemFile != null) {
                        signer = new Ed25519SignerVerifier(signingKeyPemFile, verifyingKeyPemFile); // supplied external key pair
                    } else if (jksFile != null && jksPassword != null && jksAlias != null) {
                        signer = new Ed25519SignerVerifier(new FileInputStream(jksFile), jksPassword, jksAlias); // supplied external key pair
                    } else {
                        /*
                        File outputDir = createCommand.outputDir;
                        if (outputDir == null) {
                            overAndOut(jc, "As the key pair will be generated, an output directory (to store the key pair) is required to be supplied as well. Alternatively, use one of the relevant options to supply keys");
                        }
                         */
                        var outputDir = new File(".didtoolbox");
                        if (!outputDir.exists()) {
                            outputDir.mkdirs();
                        }
                        signer.writePrivateKeyAsPem(new File(outputDir, "id_ed25519"));
                        signer.writePublicKeyAsPem(new File(outputDir, "id_ed25519.pub"));
                    }

                    var tdwBuilder = TdwCreator.builder().signer(signer);

                    didLogEntry = tdwBuilder
                            .assertionMethodKeys(assertionMethodsMap)
                            .authenticationKeys(authMap)
                            .build()
                            .create(domain, path);

                } catch (Exception e) {
                    overAndOut(jc, "Command '" + parsedCmdStr + "' failed due to: " + e.getLocalizedMessage());
                }

                System.out.println(didLogEntry);

                break;

            default:
                overAndOut(jc, "Invalid command: " + parsedCmdStr);
        }

        System.exit(0);
    }

    private static void overAndOut(JCommander jc, String message) {
        System.err.println(message);
        System.err.println();
        jc.usage();
        System.exit(1);
    }

    private String getImplementationTitle() {
        // CAUTION Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return getManifestResourceValue("Implementation-Title");
    }

    private String getImplementationVersion() {
        // CAUTION Ensure the maven-assembly-plugin manifest config param 'addDefaultImplementationEntries' is set to true
        return getManifestResourceValue("Implementation-Version");
    }
}