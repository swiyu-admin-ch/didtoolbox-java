package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.*;
import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import com.beust.jcommander.JCommander;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.time.Duration;
import java.util.HashSet;

/**
 * The class is introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.AvoidCatchingGenericException"})
final class JCommanderRunner {
    private static final String TOOLBOX_DIR = ".didtoolbox";

    private final JCommander jc;
    private final String parsedCommandName;

    JCommanderRunner(JCommander jc, String parsedCommandName) {
        this.jc = jc;
        this.parsedCommandName = parsedCommandName;
    }

    private static int printCommandError(JCommander jc, String commandName, String message) {
        jc.getConsole().println(message);
        jc.getConsole().println("");
        if (commandName != null) {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " " + commandName + " -h");
        } else {
            jc.getConsole().println("For detailed usage, run: " + ManifestUtils.getImplementationTitle() + " -h");
        }
        return 1;
    }

    /**
     * Simple helper for extracting DID method parameters in a specification-agnostic fashion.
     *
     * @param jc                {@code JCommander} object to use to display appropriate message in case of error
     * @param parsedCommandName name of the existing command to display in case of err
     * @param didLogFile        {@code File} object containing a valid DID log
     * @return a {@code DidLogMeta} object, never {@code null}
     */
    private static DidLogMeta fetchDidLogMeta(JCommander jc,
                                              String parsedCommandName,
                                              File didLogFile) {
        DidLogMeta didLogMeta = null;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:webvh log
            } catch (DidLogMetaPeekerException | IOException exc1) { // not a did:webvh log
                printCommandError(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
            }
        } catch (IOException exc) { // not a did:tdw log
            printCommandError(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
        }

        if (didLogMeta == null ||
                didLogMeta.getParams() == null ||
                didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new IllegalArgumentException("Incomplete metadata");
        }

        return didLogMeta;
    }

    private static void createPrivateKeyDirectoryIfDoesNotExist(String pathname) throws DidLogCreatorStrategyException {
        var outputDir = Path.of(pathname);
        if (!outputDir.toFile().exists()) {
            try {
                FilesPrivacy.createPrivateDirectory(outputDir, false); // may throw DirectoryNotEmptyException, SecurityException etc.
            } catch (DirectoryNotEmptyException | FileAlreadyExistsException | AccessDeniedException ex) {
                // the directory (if exists) must be empty with write access granted
                throw new IllegalArgumentException(ex);
            } catch (Throwable thr) {
                throw new DidLogCreatorStrategyException("Failed to create private directory " + pathname + " due to: " + thr.getMessage(), thr);
            }
        }
    }

    int runCreateDidLogCommand(CreateDidLogCommand command)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException, IOException,
            VcDataIntegrityCryptographicSuiteException, DidLogCreatorStrategyException, NextKeyHashesDidMethodParameterException,
            UpdateKeysDidMethodParameterException, VerificationMethodException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return 0;
        }

        var identifierRegistryUrl = command.identifierRegistryUrl;

        var didMethod = command.methodVersion; // may return null
        if (didMethod == null) {
            didMethod = CreateDidLogCommand.DEFAULT_METHOD_VERSION; // fallback
        }

        var forceOverwrite = command.forceOverwrite;

        var assertionMethods = new HashSet<VerificationMethod>();
        var assertionMethodKeys = command.assertionMethodKeys;
        if (assertionMethodKeys != null && !assertionMethodKeys.isEmpty()) {
            for (VerificationMethodParameters param : assertionMethodKeys) {
                assertionMethods.add(VerificationMethod.of(param.key, param.jwk));
            }
        } else {
            createPrivateKeyDirectoryIfDoesNotExist(TOOLBOX_DIR);
            assertionMethods.add(VerificationMethod.of("assert-key-01",
                    JwkUtils.generatePublicEC256("assert-key-01", Path.of(".didtoolbox/assert-key-01").toFile(), forceOverwrite)));
        }

        var authentications = new HashSet<VerificationMethod>();
        var authenticationKeys = command.authenticationKeys;
        if (authenticationKeys != null && !authenticationKeys.isEmpty()) {
            for (VerificationMethodParameters param : authenticationKeys) {
                authentications.add(VerificationMethod.of(param.key, param.jwk));
            }
        } else {
            createPrivateKeyDirectoryIfDoesNotExist(TOOLBOX_DIR);
            authentications.add(VerificationMethod.of("auth-key-01",
                    JwkUtils.generatePublicEC256("auth-key-01", Path.of(".didtoolbox/auth-key-01").toFile(), forceOverwrite)));
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextKeyPemFiles = command.nextVerifyingKeyPemFiles;

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            var dalekSigner = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            cryptoSuite = dalekSigner;

            var outputDir = new File(TOOLBOX_DIR);
            if (!outputDir.exists() || forceOverwrite) {
                try {
                    FilesPrivacy.createPrivateDirectory(outputDir.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
                } catch (DirectoryNotEmptyException | FileAlreadyExistsException ex) {
                    if (!outputDir.exists()) {
                        throw new IllegalArgumentException(ex); // the delete-create logic is not implemented properly
                    }
                    // ignore otherwise
                } catch (AccessDeniedException ex) {
                    return printCommandError(jc, parsedCommandName, "Access denied to " + outputDir.getPath() + " due to: " + ex.getMessage());
                } catch (Throwable thr) {
                    return printCommandError(jc, parsedCommandName, "Failed to (re)create " + outputDir.getPath() + " directory due to: " + thr.getMessage());
                }
            }

            var privateKeyFile = new File(outputDir, "id_ed25519");
            if (!privateKeyFile.exists() || forceOverwrite) {

                try {
                    // CAUTION A private key file MUST always be created with appropriate file permissions i.e. with access restricted to the current user only
                    FilesPrivacy.createPrivateFile(privateKeyFile.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
                } catch (DirectoryNotEmptyException ex) {
                    throw new IllegalArgumentException(ex); // it should be a file, not a directory
                } catch (FileAlreadyExistsException ex) {
                    if (!privateKeyFile.exists()) {
                        throw new IllegalArgumentException(ex);
                    }
                    throw ex;
                } catch (AccessDeniedException ex) {
                    return printCommandError(jc, parsedCommandName, "Access denied to private key PEM file " + privateKeyFile.getPath() + " due to: " + ex.getMessage());
                } catch (Throwable thr) {
                    return printCommandError(jc, parsedCommandName, "The private key PEM file could not be created with restricted access: " + privateKeyFile.getPath());
                }

                try {
                    dalekSigner.writePkcs8PemFile(privateKeyFile.toPath());
                    dalekSigner.writePublicKeyPemFile(new File(outputDir, privateKeyFile.getName() + ".pub").toPath());
                } catch (VcDataIntegrityCryptographicSuiteException ex) {
                    return printCommandError(jc, parsedCommandName, "Failed to persist PEM file(s) due to: " + ex.getMessage());
                }

            } else {
                return printCommandError(jc, parsedCommandName, "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + privateKeyFile.getPath());
            }
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(DidLogCreatorContext.builder()
                .didMethod(didMethod)
                .cryptographicSuite(cryptoSuite)
                .assertionMethods(assertionMethods)
                .authentications(authentications)
                // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                // Instead of calling deprecated .nextKeys(nextKeyPemFiles)
                .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextKeyPemFiles))
                .build()
                .create(identifierRegistryUrl));
        return 0;
    }

    int runUpdateDidLogCommand(UpdateDidLogCommand command)
            throws IOException, UnrecoverableEntryException, VcDataIntegrityCryptographicSuiteException, KeyStoreException,
            NoSuchAlgorithmException, KeyException, DidLogUpdaterStrategyException, NextKeyHashesDidMethodParameterException,
            UpdateKeysDidMethodParameterException, VerificationMethodException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return 0;
        }

        var didLogFile = command.didLogFile;

        var didLogMeta = fetchDidLogMeta(jc, parsedCommandName, didLogFile);

        // CAUTION At this point, it should be all in place to update to be able to update the supplied DID log

        var assertionMethods = new HashSet<VerificationMethod>();
        var updateCommandAssertionMethodKeys = command.assertionMethodKeys;
        if (updateCommandAssertionMethodKeys != null && !updateCommandAssertionMethodKeys.isEmpty()) {
            for (VerificationMethodParameters param : updateCommandAssertionMethodKeys) {
                assertionMethods.add(VerificationMethod.of(param.key, param.jwk));
            }
        }

        var authentications = new HashSet<VerificationMethod>();
        var updateCommandAuthenticationKeys = command.authenticationKeys;
        if (updateCommandAuthenticationKeys != null && !updateCommandAuthenticationKeys.isEmpty()) {
            for (VerificationMethodParameters param : updateCommandAuthenticationKeys) {
                authentications.add(VerificationMethod.of(param.key, param.jwk));
            }
        }

        if (authentications.isEmpty() && assertionMethods.isEmpty()) {
            return printCommandError(jc, parsedCommandName, "No update will take place as no verification material is supplied whatsoever");
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextVerifyingKeyPemFiles = command.nextVerifyingKeyPemFiles; // if set, denotes key pre-rotation

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            return printCommandError(jc, parsedCommandName, "Incomplete source of the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
            return printCommandError(jc, parsedCommandName, "Illegal signing (private) ed25519 key supplied");
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogUpdaterContext.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .cryptographicSuite(cryptoSuite)
                        .assertionMethods(assertionMethods)
                        .authentications(authentications)
                        // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                        .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                        // Instead of calling deprecated .nextKeys(nextVerifyingKeyPemFiles)
                        .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextVerifyingKeyPemFiles))
                        .build()
                        .update(didLogFile));
        return 0;
    }

    int runDeactivateDidLogCommand(DeactivateDidLogCommand command)
            throws IOException, UnrecoverableEntryException, VcDataIntegrityCryptographicSuiteException, KeyStoreException,
            NoSuchAlgorithmException, KeyException, DidLogDeactivatorStrategyException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return 0;
        }

        var didLogFile = command.didLogFile;
        var didLogMeta = fetchDidLogMeta(jc, parsedCommandName, didLogFile);

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            return printCommandError(jc, parsedCommandName, "No valid source of signing/verifying ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorContext.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .cryptographicSuite(cryptoSuite)
                        .build()
                        .deactivate(didLogFile));
        return 0;
    }

    int runPoPCreateCommand(CreateProofOfPossessionCommand command)
            throws IOException, ProofOfPossessionCreatorException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return 0;
        }

        // Duration after which the JWT expires
        Duration validDuration = Duration.ofDays(1);

        var nonce = command.nonce;
        var didLogFile = command.didLog;
        var privateKey = command.signingKeyPemFile;
        var kid = command.kid;

        var didLog = Files.readString(didLogFile.toPath());

        ProofOfPossessionJWSSigner signer = new EcP256ProofOfPossessionJWSSigner(privateKey.toPath(), kid);

        var proof = new ProofOfPossessionCreator(signer).create(nonce, validDuration);
        try {
            var verifier = new ProofOfPossessionVerifier(didLog);
            verifier.verify(proof, nonce);
        } catch (ProofOfPossessionVerifierException e) {
            return printCommandError(jc, parsedCommandName, "Failed to verify generated proof: %s".formatted(e.getLocalizedMessage()));
        }

        jc.getConsole().println(proof.serialize());
        return 0;
    }

    int runPoPVerifyCommand(VerifyProofOfPossessionCommand command) throws IOException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return 0;
        }

        var didLogFile = command.didLogFile;
        var nonce = command.nonce;
        var jwt = command.jwt;

        var didLog = Files.readString(didLogFile.toPath());

        try {
            new ProofOfPossessionVerifier(didLog)
                    .verify(jwt, nonce);
            jc.getConsole().println("Provided JWT is valid.");
        } catch (ProofOfPossessionVerifierException e) {
            return printCommandError(jc, parsedCommandName, "Provided JWT is invalid: " + e.getLocalizedMessage());
        }
        return 0;
    }

    /**
     * @param command containing the parameters to initialize the cryptographic suite
     * @return the cryptographic suite, may return null if none is configured through the command parameters.
     * @throws VcDataIntegrityCryptographicSuiteException if it fails to initialize the corresponding cryptographic suite
     */
    private VcDataIntegrityCryptographicSuite getCryptoGraphicSuite(AbstractDidLogCommandBase command) throws VcDataIntegrityCryptographicSuiteException {
        if (command.signingKeyPemFile != null) {
            return new EdDsaJcs2022VcDataIntegrityCryptographicSuite(command.signingKeyPemFile.toPath());
        } else if (command.jksFile != null && command.jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            try {
                return new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Files.newInputStream(command.jksFile.toPath()), command.jksPassword, command.jksAlias, command.jksPassword); // supplied external key pair
            } catch (IOException e) {
                throw new VcDataIntegrityCryptographicSuiteException("Unable to load KeyStore:" + e.getMessage(), e);
            }
        } else if (command.securosysPrimusKeyStoreLoader != null && command.primusKeyAlias != null) {
            try {
                return new PrimusEd25519VerificationMethodKeyProviderImpl(command.securosysPrimusKeyStoreLoader, command.primusKeyAlias, command.primusKeyPassword); // supplied external key pair
            } catch (UnrecoverableEntryException | KeyStoreException | NoSuchAlgorithmException |KeyException e) {
                throw new VcDataIntegrityCryptographicSuiteException("Failed to initialize primus:" + e.getMessage(),e);
            }
        }
        return null;
    }
}