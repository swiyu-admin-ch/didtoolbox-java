package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519ProofOfPossessionJWSSignerImpl;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.beust.jcommander.UnixStyleUsageFormatter;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

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

        var createDidLogCommand = new CreateDidLogCommand();
        var updateDidLogCommand = new UpdateDidLogCommand();
        var deactivateCommand = new DeactivateDidLogCommand();
        var createProofOfPossessionCommand = new CreateProofOfPossessionCommand();
        var verifyProofOfPossessionCommand = new VerifyProofOfPossessionCommand();
        var jc = JCommander.newBuilder()
                .addObject(main)
                .addCommand(CreateDidLogCommand.COMMAND_NAME, createDidLogCommand)
                .addCommand(UpdateDidLogCommand.COMMAND_NAME, updateDidLogCommand)
                .addCommand(DeactivateDidLogCommand.COMMAND_NAME, deactivateCommand)
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

        try {
            switch (parsedCommandName) {
                case CreateDidLogCommand.COMMAND_NAME ->
                        runCreateDidLogCommand(jc, parsedCommandName, createDidLogCommand);
                case UpdateDidLogCommand.COMMAND_NAME ->
                        runUpdateDidLogCommand(jc, parsedCommandName, updateDidLogCommand);
                case DeactivateDidLogCommand.COMMAND_NAME ->
                        runDeactivateDidLogCommand(jc, parsedCommandName, deactivateCommand);
                case CreateProofOfPossessionCommand.COMMAND_NAME ->
                        runPoPCreateCommand(jc, parsedCommandName, createProofOfPossessionCommand);
                case VerifyProofOfPossessionCommand.COMMAND_NAME ->
                        runPoPVerifyCommand(jc, parsedCommandName, verifyProofOfPossessionCommand);
                default -> overAndOut(jc, null, "Invalid command: " + parsedCommandName);
            }
        } catch (Exception e) {
            overAndOut(jc, parsedCommandName, "Running command '" + parsedCommandName + "' failed due to: " + e.getLocalizedMessage());
        }

        System.exit(0);
    }

    private static void runCreateDidLogCommand(JCommander jc, String parsedCommandName, CreateDidLogCommand command) throws Exception {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        URL identifierRegistryUrl = command.identifierRegistryUrl;

        var didMethod = DidMethodEnum.parse(command.methodVersion); // may return null
        if (didMethod == null) {
            didMethod = CreateDidLogCommand.DEFAULT_METHOD_VERSION; // fallback
        }

        Map<String, String> assertionMethodKeysMap = new HashMap<>();
        var assertionMethodKeys = command.assertionMethodKeys;
        if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {
            for (VerificationMethodParameters param : assertionMethodKeys) {
                assertionMethodKeysMap.put(param.key, param.jwk);
            }
        }

        Map<String, String> authenticationKeysMap = new HashMap<>();
        var authenticationKeys = command.authenticationKeys;
        if (authenticationKeys != null && !authenticationKeys.isEmpty()) {
            for (VerificationMethodParameters param : authenticationKeys) {
                authenticationKeysMap.put(param.key, param.jwk);
            }
        }

        var signingKeyPemFile = command.signingKeyPemFile;
        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        boolean forceOverwrite = command.forceOverwrite;

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

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        System.out.println(DidLogCreatorStrategy.builder()
                .didMethod(didMethod)
                .verificationMethodKeyProvider(signer)
                .assertionMethodKeys(assertionMethodKeysMap)
                .authenticationKeys(authenticationKeysMap)
                .updateKeys(verifyingKeyPemFiles)
                .forceOverwrite(forceOverwrite)
                .build()
                .create(identifierRegistryUrl));
    }

    private static void runUpdateDidLogCommand(JCommander jc, String parsedCommandName, UpdateDidLogCommand command) throws Exception {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        var didLogFile = command.didLogFile;

        var didLogMeta = fetchDidLogMeta(jc, parsedCommandName, didLogFile);

        // CAUTION At this point, it should be all in place to update to be able to update the supplied DID log

        Map<String, String> assertionMethodKeysMap = new HashMap<>();
        var updateCommandAssertionMethodKeys = command.assertionMethodKeys;
        if (updateCommandAssertionMethodKeys != null && !updateCommandAssertionMethodKeys.isEmpty()) {
            for (VerificationMethodParameters param : updateCommandAssertionMethodKeys) {
                assertionMethodKeysMap.put(param.key, param.jwk);
            }
        }

        Map<String, String> authenticationKeysMap = new HashMap<>();
        var updateCommandAuthenticationKeys = command.authenticationKeys;
        if (updateCommandAuthenticationKeys != null && !updateCommandAuthenticationKeys.isEmpty()) {
            for (VerificationMethodParameters param : updateCommandAuthenticationKeys) {
                authenticationKeysMap.put(param.key, param.jwk);
            }
        }

        if (authenticationKeysMap.isEmpty() && assertionMethodKeysMap.isEmpty()) {
            overAndOut(jc, parsedCommandName, "No update will take place as no verification material is supplied whatsoever");
        }

        var signingKeyPemFile = command.signingKeyPemFile;
        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        VerificationMethodKeyProvider signer = null; // no default, must be supplied

        if (signingKeyPemFile != null && verifyingKeyPemFiles != null) {

            String matchingUpdateKey = null;
            for (var key : didLogMeta.getParams().getUpdateKeys()) {
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

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        assert didLogMeta != null;
        System.out.println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogUpdaterStrategy.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .verificationMethodKeyProvider(signer)
                        .assertionMethodKeys(assertionMethodKeysMap)
                        .authenticationKeys(authenticationKeysMap)
                        .updateKeys(verifyingKeyPemFiles)
                        .build()
                        .update(didLogFile));
    }

    private static void runDeactivateDidLogCommand(JCommander jc, String parsedCommandName, DeactivateDidLogCommand command) throws Exception {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        var didLogFile = command.didLogFile;

        var didLogMeta = fetchDidLogMeta(jc, parsedCommandName, didLogFile);

        var signingKeyPemFile = command.signingKeyPemFile;

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        VerificationMethodKeyProvider signer = null; // no default, must be supplied

        if (signingKeyPemFile != null) {

            String matchingUpdateKey = null;
            assert didLogMeta != null;
            // CAUTION In case the supplied DID log have already been deactivated (i.e. "parameters":{"deactivated":true,"updateKeys":[]}),
            //         the updateKeys collection would be null
            if (didLogMeta.getParams().getUpdateKeys() != null) {
                for (var key : didLogMeta.getParams().getUpdateKeys()) {
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
            }

        } else if (jksFile != null && jksPassword != null && jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            signer = new Ed25519VerificationMethodKeyProviderImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair

        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

            signer = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

        } else {
            overAndOut(jc, parsedCommandName, "No source for the (signing/verifying) keys supplied. Use one of the relevant options to supply keys");
        }

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        System.out.println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorStrategy.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .verificationMethodKeyProvider(signer)
                        .build()
                        .deactivate(didLogFile));
    }

    private static void runPoPCreateCommand(JCommander jc, String parsedCommandName, CreateProofOfPossessionCommand command) throws Exception {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        // Duration after which the JWT expires
        Duration validDuration = Duration.ofDays(1);

        var nonce = command.nonce;
        var signingKeyPemFile = command.signingKeyPemFile;
        var verifyingKeyPemFile = command.verifyingKeyPemFile;

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        ProofOfPossessionJWSSigner signer = null;

        if (signingKeyPemFile != null && verifyingKeyPemFile == null) {

            overAndOut(jc, parsedCommandName, "No matching verifying (public) ed25519 key supplied");

        } else if (signingKeyPemFile != null) { // at this point, verifyingKeyPemFiles must be non-null already

            try {
                signer = new Ed25519ProofOfPossessionJWSSignerImpl(new FileReader(signingKeyPemFile), new FileReader(verifyingKeyPemFile)); // supplied external key pair
            } catch (Exception ex) {
                overAndOut(jc, parsedCommandName, "The supplied ed25519 key pair mismatch: " + ex.getLocalizedMessage());
            }

        } else if (jksFile != null && jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            signer = new Ed25519ProofOfPossessionJWSSignerImpl(new FileInputStream(jksFile), jksPassword, jksAlias, jksPassword); // supplied external key pair
        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {
            signer = new PrimusEd25519ProofOfPossessionJWSSignerImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair
        } else {
            overAndOut(jc, parsedCommandName, "No source for the (signing) ed25519 key supplied. Use one of the relevant options to supply keys");
        }

        var proof = new ProofOfPossessionCreator(signer)
                .create(nonce, validDuration);

        System.out.println(proof.serialize());
    }

    private static void runPoPVerifyCommand(JCommander jc, String parsedCommandName, VerifyProofOfPossessionCommand command) throws IOException {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        var didLogFile = command.didLogFile;
        var nonce = command.nonce;
        var jwt = command.jwt;

        var didLog = Files.readString(didLogFile.toPath());

        try {
            new ProofOfPossessionVerifier(didLog)
                    .verify(jwt, nonce);
            System.out.println("Provided JWT is valid.");
        } catch (ProofOfPossessionVerifierException e) {
            overAndOut(jc, parsedCommandName, "Provided JWT is invalid: " + e.getLocalizedMessage());
        }
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

    private static DidLogMeta fetchDidLogMeta(JCommander jc,
                                              String parsedCommandName,
                                              File didLogFile) {
        DidLogMeta didLogMeta = null;
        try {
            return TdwDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                return WebVerifiableHistoryDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:webvh log
            } catch (DidLogMetaPeekerException | IOException exc1) { // not a did:webvh log
                overAndOut(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
            }
        } catch (IOException exc) { // not a did:tdw log
            overAndOut(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
        }

        if (didLogMeta == null || didLogMeta.getParams() == null || didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new RuntimeException("Incomplete metadata");
        }

        return null;
    }
}