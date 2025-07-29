package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusKeyStoreLoader;
import ch.admin.eid.didtoolbox.TrustDidWeb;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.net.URL;
import java.nio.file.*;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Main {

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox",
            help = true)
    boolean help;

    @Parameter(names = {"--version", "-V"},
            description = "Display version")
    boolean version;

    public static void main(String... args) {
        var main = new Main();

        var createCommand = new CreateTdwCommand();
        var updateCommand = new UpdateTdwCommand();
        var deactivateCommand = new DeactivateTdwCommand();
        var createProofOfPossessionCommand = new CreateProofOfPossessionCommand();
        var verifyProofOfPossessionCommand = new VerifyProofOfPossessionCommand();
        var jc = JCommander.newBuilder()
                .addObject(main)
                .addCommand(CreateTdwCommand.COMMAND_NAME, createCommand)
                .addCommand(UpdateTdwCommand.COMMAND_NAME, updateCommand)
                .addCommand(DeactivateTdwCommand.COMMAND_NAME, deactivateCommand)
                .addCommand(CreateProofOfPossessionCommand.COMMAND_NAME, createProofOfPossessionCommand)
                .addCommand(VerifyProofOfPossessionCommand.COMMAND_NAME, verifyProofOfPossessionCommand)
                .programName(ManifestUtils.getImplementationTitle())
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
            System.out.println(ManifestUtils.getImplementationTitle() + " " + ManifestUtils.getImplementationVersion());
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
        PrimusKeyStoreLoader primus;
        String primusKeyAlias;
        String primusKeyPassword;
        File didLogFile;
        Map<String, String> assertionMethodKeysMap;
        Map<String, String> authenticationKeysMap;
        String nonce;

        switch (parsedCommandName) {

            case CreateTdwCommand.COMMAND_NAME:

                if (createCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                URL identifierRegistryUrl = createCommand.identifierRegistryUrl;

                var methodVersion = createCommand.methodVersion;
                if (methodVersion == null) {
                    methodVersion = CreateTdwCommand.DEFAULT_METHOD_VERSION;
                } else if (!methodVersion.equals(CreateTdwCommand.DEFAULT_METHOD_VERSION)) {
                    overAndOut(jc, parsedCommandName, "Supplied method version is not supported: '" + methodVersion + "'. Currently supported is: " + CreateTdwCommand.DEFAULT_METHOD_VERSION);
                }

                assertionMethodKeysMap = new HashMap<>();
                var assertionMethodKeys = createCommand.assertionMethodKeys;
                if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {
                    for (VerificationMethodParameters param : assertionMethodKeys) {
                        assertionMethodKeysMap.put(param.key, param.jwk);
                    }
                }

                authenticationKeysMap = new HashMap<>();
                var authenticationKeys = createCommand.authenticationKeys;
                if (authenticationKeys != null && !authenticationKeys.isEmpty()) {
                    for (VerificationMethodParameters param : authenticationKeys) {
                        authenticationKeysMap.put(param.key, param.jwk);
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

                boolean forceOverwrite = createCommand.forceOverwrite;

                String didLogEntry = null;
                try {

                    VerificationMethodKeyProvider signer = null;

                    if (signingKeyPemFile != null && verifyingKeyPemFiles == null) {

                        overAndOut(jc, parsedCommandName, "No matching verifying (public) ed25519 key supplied");

                    } else if (signingKeyPemFile != null) { // at this point, verifyingKeyPemFiles must be non-null already

                        File verifyingKeyPemFile = null;
                        for (var pemFile : verifyingKeyPemFiles) {
                            try {
                                signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(signingKeyPemFile), new FileReader(pemFile)); // supplied external key pair
                                // At this point, the matching verifying key is detected, so we are free to break from the loop
                                verifyingKeyPemFile = pemFile;
                                break;
                            } catch (Exception ignoreNonMatchingKey) {
                            }
                        }

                        if (verifyingKeyPemFile == null) {
                            overAndOut(jc, parsedCommandName, "No matching verifying (public) ed25519 key supplied");
                        }

                    } else if (jksFile != null && jksAlias != null) {

                        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
                        signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair
                        // TODO Populate verifyingKeyPemFiles (for each jksAlias) from the JKS by calling signer.writePublicKeyAsPem(tempPublicKeyPemFile);

                    } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

                        signer = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

                    } else {

                        signer = new Ed25519VerificationMethodKeyProviderImpl();

                        /*
                        File outputDir = createCommand.outputDir;
                        if (outputDir == null) {
                            overAndOut(jc, "As the key pair will be generated, an output directory (to store the key pair) is required to be supplied as well. Alternatively, use one of the relevant options to supply keys");
                        }
                         */
                        var outputDir = new File(".didtoolbox");
                        if (!outputDir.exists() || forceOverwrite) {

                            try {
                                FilesPrivacy.createPrivateDirectory(outputDir.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
                            } catch (DirectoryNotEmptyException | FileAlreadyExistsException ex) {
                                if (!outputDir.exists()) {
                                    throw new RuntimeException(ex); // the delete-create logic is not implemented properly
                                }
                                // ignore otherwise
                            } catch (AccessDeniedException ex) {
                                overAndOut(jc, parsedCommandName, "Access denied to " + outputDir.getPath() + " due to: " + ex.getMessage());
                            } catch (Throwable thr) {
                                overAndOut(jc, parsedCommandName, "Failed to (re)create " + outputDir.getPath() + " directory due to: " + thr.getMessage());
                            }
                        }

                        var privateKeyFile = new File(outputDir, "id_ed25519");
                        if (!privateKeyFile.exists() || forceOverwrite) {

                            try {
                                // CAUTION A private key file MUST always be created with appropriate file permissions i.e. with access restricted to the current user only
                                FilesPrivacy.createPrivateFile(privateKeyFile.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
                            } catch (DirectoryNotEmptyException ex) {
                                throw new RuntimeException(ex); // it should be a file, not a directory
                            } catch (FileAlreadyExistsException ex) {
                                if (!privateKeyFile.exists()) {
                                    throw new RuntimeException(ex);
                                }
                                throw ex;
                            } catch (AccessDeniedException ex) {
                                overAndOut(jc, parsedCommandName, "Access denied to private key PEM file " + privateKeyFile.getPath() + " due to: " + ex.getMessage());
                            } catch (Throwable thr) {
                                overAndOut(jc, parsedCommandName, "The private key PEM file could not be created with restricted access: " + privateKeyFile.getPath());
                            }

                            ((Ed25519VerificationMethodKeyProviderImpl) signer).writePrivateKeyAsPem(privateKeyFile);
                            ((Ed25519VerificationMethodKeyProviderImpl) signer).writePublicKeyAsPem(new File(outputDir, privateKeyFile.getName() + ".pub"));
                        } else {
                            overAndOut(jc, parsedCommandName, "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + privateKeyFile.getPath());
                        }
                    }

                    var tdwBuilder = TdwCreator.builder().verificationMethodKeyProvider(signer);

                    didLogEntry = tdwBuilder
                            .assertionMethodKeys(assertionMethodKeysMap)
                            .authenticationKeys(authenticationKeysMap)
                            .updateKeys(verifyingKeyPemFiles)
                            .forceOverwrite(forceOverwrite)
                            .build()
                            .create(identifierRegistryUrl);

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                System.out.println(didLogEntry);

                break;

            case UpdateTdwCommand.COMMAND_NAME:

                if (updateCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                didLogFile = updateCommand.didLogFile;

                assertionMethodKeysMap = new HashMap<>();
                var updateCommandAssertionMethodKeys = updateCommand.assertionMethodKeys;
                if (updateCommandAssertionMethodKeys != null && !updateCommandAssertionMethodKeys.isEmpty()) {
                    for (VerificationMethodParameters param : updateCommandAssertionMethodKeys) {
                        assertionMethodKeysMap.put(param.key, param.jwk);
                    }
                }

                authenticationKeysMap = new HashMap<>();
                var updateCommandAuthenticationKeys = updateCommand.authenticationKeys;
                if (updateCommandAuthenticationKeys != null && !updateCommandAuthenticationKeys.isEmpty()) {
                    for (VerificationMethodParameters param : updateCommandAuthenticationKeys) {
                        authenticationKeysMap.put(param.key, param.jwk);
                    }
                }

                if (authenticationKeysMap.isEmpty() && assertionMethodKeysMap.isEmpty()) {
                    overAndOut(jc, parsedCommandName, "No update will take place as no verification material is supplied whatsoever");
                }

                signingKeyPemFile = updateCommand.signingKeyPemFile;
                verifyingKeyPemFiles = updateCommand.verifyingKeyPemFiles;

                jksFile = updateCommand.jksFile;
                jksPassword = updateCommand.jksPassword;
                jksAlias = updateCommand.jksAlias;

                primus = updateCommand.securosysPrimusKeyStoreLoader;
                primusKeyAlias = updateCommand.primusKeyAlias;
                primusKeyPassword = updateCommand.primusKeyPassword;

                try {

                    VerificationMethodKeyProvider signer = null; // no default, must be supplied

                    if (signingKeyPemFile != null && verifyingKeyPemFiles != null) {

                        var didLogMeta = DidLogMetaPeeker.peek(Files.readString(didLogFile.toPath()));
                        String matchingUpdateKey = null;
                        for (var key : didLogMeta.params.updateKeys) {
                            try {
                                // the signing key is supplied externally, but verifying key should be already among updateKeys
                                signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(signingKeyPemFile), key);
                                // At this point, the matching verifying key is detected, so we are free to break from the loop
                                matchingUpdateKey = key;
                                break;
                            } catch (Exception ignoreNonMatchingKey) {
                            }
                        }

                        if (matchingUpdateKey == null) {
                            overAndOut(jc, parsedCommandName, "No matching signing (private) ed25519 key supplied");
                        }

                    } else if (jksFile != null && jksAlias != null) {
                        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
                        signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair

                    } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

                        signer = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

                    } else {
                        overAndOut(jc, parsedCommandName, "No source for the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys");
                    }

                    var tdwBuilder = TdwUpdater.builder().verificationMethodKeyProvider(signer);

                    var newLogEntry = tdwBuilder
                            .assertionMethodKeys(assertionMethodKeysMap)
                            .authenticationKeys(authenticationKeysMap)
                            .updateKeys(verifyingKeyPemFiles)
                            .build()
                            .update(didLogFile);

                    // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
                    System.out.println(new StringBuilder(Files.readString(didLogFile.toPath()).trim()).append(System.lineSeparator()).append(newLogEntry));

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                break;

            case DeactivateTdwCommand.COMMAND_NAME:

                if (deactivateCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                didLogFile = deactivateCommand.didLogFile;

                signingKeyPemFile = deactivateCommand.signingKeyPemFile;

                jksFile = deactivateCommand.jksFile;
                jksPassword = deactivateCommand.jksPassword;
                jksAlias = deactivateCommand.jksAlias;

                primus = deactivateCommand.securosysPrimusKeyStoreLoader;
                primusKeyAlias = deactivateCommand.primusKeyAlias;
                primusKeyPassword = deactivateCommand.primusKeyPassword;

                try {

                    VerificationMethodKeyProvider signer = null; // no default, must be supplied

                    if (signingKeyPemFile != null) {

                        var didLogMeta = DidLogMetaPeeker.peek(Files.readString(didLogFile.toPath()));
                        String matchingUpdateKey = null;
                        for (var key : didLogMeta.params.updateKeys) {
                            try {
                                // the signing key is supplied externally, but verifying key should be already among updateKeys
                                signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(signingKeyPemFile), key);
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

                    } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

                        signer = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

                    } else {
                        overAndOut(jc, parsedCommandName, "No source for the (signing/verifying) keys supplied. Use one of the relevant options to supply keys");
                    }

                    var newLogEntry = TdwDeactivator.builder()
                            .verificationMethodKeyProvider(signer)
                            .build()
                            .deactivate(didLogFile);

                    // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
                    System.out.println(new StringBuilder(Files.readString(didLogFile.toPath()).trim()).append(System.lineSeparator()).append(newLogEntry));

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                break;

            case CreateProofOfPossessionCommand.COMMAND_NAME:

                if (createProofOfPossessionCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                nonce = createProofOfPossessionCommand.nonce;
                didLogFile = createProofOfPossessionCommand.didLogFile;
                signingKeyPemFile = createProofOfPossessionCommand.signingKeyPemFile;

                jksFile = updateCommand.jksFile;
                jksPassword = updateCommand.jksPassword;
                jksAlias = updateCommand.jksAlias;

                primus = updateCommand.securosysPrimusKeyStoreLoader;
                primusKeyAlias = updateCommand.primusKeyAlias;
                primusKeyPassword = updateCommand.primusKeyPassword;
                try {
                    PrivateKey privateKey;
                    if (signingKeyPemFile != null) {
                        var privatePemBytes = PemUtils.readPemObject(new FileReader(createProofOfPossessionCommand.signingKeyPemFile));
                        privateKey = PemUtils.getPrivateKeyEd25519(privatePemBytes);

                    } else if (jksFile != null && jksAlias != null) {
                        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
                        var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair
                        privateKey = signer.keyPair.getPrivate();

                    } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {
                        var primusSigner = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair
                        privateKey = primusSigner.keyPair.getPrivate();

                    } else {
                        overAndOut(jc, parsedCommandName, "No source for the (signing) ed25519 key supplied. Use one of the relevant options to supply keys");
                        return;
                    }

                    var log = String.join("\n", Files.readAllLines(didLogFile.toPath()));
                    var didDocId = DidLogMetaPeeker.peek(log).didDocId;
                    var didWeb = TrustDidWeb.Companion.read(didDocId, log);

                    var proof = ProofOfPossessionUtil.createProofOfPossession(privateKey, didWeb, nonce);
                    System.out.println(proof.serialize());

                } catch (Exception e) {
                    overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
                }

                break;

            case VerifyProofOfPossessionCommand.COMMAND_NAME:
                if (verifyProofOfPossessionCommand.help) {
                    jc.usage(parsedCommandName);
                    System.exit(0);
                }

                didLogFile = verifyProofOfPossessionCommand.didLogFile;
                nonce = verifyProofOfPossessionCommand.nonce;
                var jwt = verifyProofOfPossessionCommand.jwt;

                try {
                    var log = String.join("\n", Files.readAllLines(didLogFile.toPath()));
                    var didDocId = DidLogMetaPeeker.peek(log).didDocId;
                    var didWeb = TrustDidWeb.Companion.read(didDocId, log);

                    try {
                        ProofOfPossessionUtil.verify(jwt, nonce, didWeb);
                        System.out.println("Provided JWT is valid.");
                    } catch (ProofOfPossessionVerificationException e) {
                        System.out.println("Provided JWT is invalid due to: " + e.getLocalizedMessage());
                    }
                    System.exit(0);
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
        jc.getConsole().println(message);
        jc.getConsole().println("");
        if (commandName != null) {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " " + commandName + " -h");
        } else {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " -h");
        }
        System.exit(1);
    }

}