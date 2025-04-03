package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.security.SecurosysPrimusKeyStoreLoader;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.jar.Manifest;

import static ch.admin.bj.swiyu.didtoolbox.CreateTdwCommand.DEFAULT_METHOD_VERSION;

class Main {

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
        var updateCommand = new UpdateTdwCommand();
        var jc = JCommander.newBuilder()
                .addObject(main)
                .addCommand("create", createCommand)
                .addCommand("update", updateCommand)
                .programName(main.getImplementationTitle())
                .columnSize(150)
                .build();

        var usageFormatter = new UnixStyleUsageFormatter(jc);
        jc.setUsageFormatter(usageFormatter);

        try {
            jc.parse(args);
        } catch (ParameterException e) {
            overAndOut(jc, null, e.getLocalizedMessage());
        }

        if (main.version) {
            System.out.println(main.getImplementationTitle() + " " + main.getImplementationVersion());
            System.exit(0);
        }

        if (main.help) {
            jc.usage();
            System.exit(0);
        }

        var parsedCommandName = jc.getParsedCommand();
        if (parsedCommandName == null) {
            jc.usage();
            System.exit(1);
        }

        File signingKeyPemFile;
        Set<File> verifyingKeyPemFiles;
        File jksFile;
        String jksPassword;
        String jksAlias;
        SecurosysPrimusKeyStoreLoader primus;
        String primusKeyAlias;
        String primusKeyPassword;

        switch (parsedCommandName) {

            case "create":

                if (createCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                URL identifierRegistryUrl = createCommand.identifierRegistryUrl;

                var methodVersion = createCommand.methodVersion;
                if (methodVersion == null) {
                    methodVersion = DEFAULT_METHOD_VERSION;
                } else if (!methodVersion.equals(DEFAULT_METHOD_VERSION)) {
                    overAndOut(jc, parsedCommandName, "Supplied method version is not supported: '" + methodVersion + "'. Currently supported is: " + DEFAULT_METHOD_VERSION);
                }

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

                signingKeyPemFile = createCommand.signingKeyPemFile;
                verifyingKeyPemFiles = createCommand.verifyingKeyPemFiles;

                jksFile = createCommand.jksFile;
                jksPassword = createCommand.jksPassword;
                jksAlias = createCommand.jksAlias;

                primus = createCommand.securosysPrimusKeyStoreLoader;
                primusKeyAlias = createCommand.primusKeyAlias;
                primusKeyPassword = createCommand.primusKeyPassword;

                if (signingKeyPemFile != null && verifyingKeyPemFiles != null &&
                        jksFile != null && jksPassword != null && jksAlias != null &&
                        primus != null && primusKeyAlias != null && primusKeyPassword != null) {
                    overAndOut(jc, parsedCommandName, "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
                }

                boolean forceOverwrite = createCommand.forceOverwrite;

                String didLogEntry = null;
                try {

                    var signer = new Ed25519VerificationMethodKeyProviderImpl();

                    if (signingKeyPemFile != null && verifyingKeyPemFiles != null) {

                        File verifyingKeyPemFile = null;
                        for (var pemFile : verifyingKeyPemFiles) {
                            try {
                                signer = new Ed25519VerificationMethodKeyProviderImpl(signingKeyPemFile, pemFile); // supplied external key pair
                                // At this point, the matching verifying key is detected, so we are free to break from the loop
                                verifyingKeyPemFile = pemFile;
                                break;
                            } catch (Exception ignoreNonMatchingKey) {
                            }
                        }

                        if (verifyingKeyPemFile == null) {
                            overAndOut(jc, parsedCommandName, "No matching verifying key supplied");
                        }

                    } else if (jksFile != null && jksPassword != null && jksAlias != null) {

                        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
                        signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair
                        // TODO Populate verifyingKeyPemFiles (for each jksAlias) from the JKS by calling signer.writePublicKeyAsPem(tempPublicKeyPemFile);

                    } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

                        signer = new Ed25519VerificationMethodKeyProviderImpl(primus.getKeyStore(), primusKeyAlias, primusKeyPassword); // supplied external key pair

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
                        var privateKeyFile = new File(outputDir, "id_ed25519");
                        var publicKeyFile = new File(outputDir, "id_ed25519.pub");
                        if (!privateKeyFile.exists() || forceOverwrite) {
                            signer.writePrivateKeyAsPem(privateKeyFile);
                            signer.writePublicKeyAsPem(publicKeyFile);
                        } else {
                            overAndOut(jc, parsedCommandName, "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + privateKeyFile.getPath());
                        }
                    }

                    var tdwBuilder = TdwCreator.builder().verificationMethodKeyProvider(signer);

                    didLogEntry = tdwBuilder
                            .assertionMethodKeys(assertionMethodsMap)
                            .authenticationKeys(authMap)
                            .updateKeys(verifyingKeyPemFiles)
                            .forceOverwrite(forceOverwrite)
                            .build()
                            .create(identifierRegistryUrl);

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                System.out.println(didLogEntry);

                break;

            case "update":

                if (updateCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                File didLogFile = updateCommand.didLogFile;

                assertionMethodsMap = new HashMap<>();
                var updateCommandAssertionMethodKeys = updateCommand.assertionMethodKeys;
                if (updateCommandAssertionMethodKeys != null && !updateCommandAssertionMethodKeys.isEmpty()) {
                    for (UpdateTdwCommand.VerificationMethodParameters param : updateCommandAssertionMethodKeys) {
                        assertionMethodsMap.put(param.key, param.jwk);
                    }
                }

                authMap = new HashMap<>();
                var updateCommandAuthenticationKeys = updateCommand.authenticationKeys;
                if (updateCommandAuthenticationKeys != null && !updateCommandAuthenticationKeys.isEmpty()) {
                    for (UpdateTdwCommand.VerificationMethodParameters param : updateCommandAuthenticationKeys) {
                        authMap.put(param.key, param.jwk);
                    }
                }

                if (authMap.isEmpty() && assertionMethodsMap.isEmpty()) {
                    overAndOut(jc, parsedCommandName, "No update will take place as no verification material is supplied whatsoever");
                }

                signingKeyPemFile = updateCommand.signingKeyPemFile;
                verifyingKeyPemFiles = updateCommand.verifyingKeyPemFiles;

                jksFile = updateCommand.jksFile;
                jksPassword = updateCommand.jksPassword;
                jksAlias = updateCommand.jksAlias;

                if (signingKeyPemFile != null && verifyingKeyPemFiles != null &&
                        jksFile != null && jksPassword != null && jksAlias != null) {
                    overAndOut(jc, parsedCommandName, "Supplied source for the (signing/verifying) keys is ambiguous. Use one of the relevant options to supply keys");
                }

                try {

                    Ed25519VerificationMethodKeyProviderImpl signer = null; // no default, must be supplied
                    if (signingKeyPemFile != null && verifyingKeyPemFiles != null) {

                        var didLogMeta = DidLogMetaPeeker.peek(Files.readString(didLogFile.toPath()));
                        String matchingUpdateKey = null;
                        for (var key : didLogMeta.params.updateKeys) {
                            try {
                                // the signing key is supplied externally, but verifying key should be already among updateKeys
                                signer = new Ed25519VerificationMethodKeyProviderImpl(signingKeyPemFile, key);
                                // At this point, the matching verifying key is detected, so we are free to break from the loop
                                matchingUpdateKey = key;
                                break;
                            } catch (Exception ignoreNonMatchingKey) {
                            }
                        }

                        if (matchingUpdateKey == null) {
                            overAndOut(jc, parsedCommandName, "No matching signing key supplied");
                        }

                    } else if (jksFile != null && jksPassword != null && jksAlias != null) {
                        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
                        signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair
                    } else {
                        overAndOut(jc, parsedCommandName, "No source for the (signing/verifying) keys supplied. Use one of the relevant options to supply keys");
                    }

                    var tdwBuilder = TdwUpdater.builder().verificationMethodKeyProvider(signer);

                    var newLogEntry = tdwBuilder
                            .assertionMethodKeys(assertionMethodsMap)
                            .authenticationKeys(authMap)
                            .updateKeys(verifyingKeyPemFiles)
                            .build()
                            .update(didLogFile);

                    // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
                    System.out.println(new StringBuilder(Files.readString(didLogFile.toPath()).trim()).append(System.lineSeparator()).append(newLogEntry));

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                break;

            default:
                overAndOut(jc, null, "Invalid command: " + parsedCommandName);
        }

        System.exit(0);
    }

    private static void overAndOut(JCommander jc, String commandName, String message) {
        System.err.println(message);
        System.err.println();
        if (commandName != null) {
            jc.usage(commandName);
        } else {
            jc.usage();
        }
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