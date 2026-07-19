package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.*;
import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.HsmProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import com.nimbusds.jose.JOSEException;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static ch.admin.bj.swiyu.didtoolbox.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY;
import static ch.admin.bj.swiyu.didtoolbox.jcommander.CommandParameterNames.PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY;

/**
 * The class is introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.AvoidCatchingGenericException"})
public final class JCommanderRunner {
    private static final String DEFAULT_BASE_PATH = "./.didtoolbox";

    private final JCommander jc;
    private final String parsedCommandName;
    private final String basePath;

    /**
     * Creates a JCommandRunner intended to run the provided command.
     *
     * @param jc
     * @param parsedCommandName
     * @param basePath path to the directory to save generated keys in
     */
    public JCommanderRunner(JCommander jc, String parsedCommandName, String basePath) {
        if (basePath.isEmpty()) {
            throw new IllegalArgumentException("Provided 'basePath' is empty, expected a value.");
        }
        this.jc = jc;
        this.parsedCommandName = parsedCommandName;
        this.basePath = basePath;
    }

    /**
     * Creates a JCommandRunner intended to run the provided command.
     * Stores generated key material in the `./.didtoolbox` directory
     *
     * @param jc
     * @param parsedCommandName
     */
    public JCommanderRunner(JCommander jc, String parsedCommandName) {
        this(jc, parsedCommandName, DEFAULT_BASE_PATH);
    }

    /**
     * Simple helper for extracting DID method parameters in a specification-agnostic fashion.
     *
     * @param didLogFile        {@code File} object containing a valid DID log
     * @return a {@code DidLogMeta} object, never {@code null}
     */
    private DidLogMeta fetchDidLogMeta( File didLogFile) throws CommandException {
        DidLogMeta didLogMeta;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(Files.readString(didLogFile.toPath())); // assume a did:webvh log
            } catch (DidLogMetaPeekerException | IOException exc1) { // not a did:webvh log
                throw new CommandException("The supplied file contains unsupported DID log format: " + didLogFile.getName(), exc1); // NOPMD PreserveStackTrace: false positive
            }
        } catch (IOException exc) { // not a did:tdw log
            throw new CommandException("The supplied file contains unsupported DID log format: " + didLogFile.getName(), exc);
        }

        if (didLogMeta.getParams() == null ||
                didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new IllegalArgumentException("Incomplete metadata");
        }

        return didLogMeta;
    }

    void runCreateDidLogCommand(CreateDidLogCommand command) throws VerificationMethodException, DidLogCreatorStrategyException, IOException, VcDataIntegrityCryptographicSuiteException, CommandException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return;
        }

        var identifierRegistryUrl = command.identifierRegistryUrl;

        var didMethod = command.methodVersion; // may return null
        if (didMethod == null) {
            didMethod = CreateDidLogCommand.DEFAULT_METHOD_VERSION; // fallback
        }

        var assertionMethods = command.getAssertionMethods(getOutputDir().toPath());
        var authentications = command.getAuthentications(getOutputDir().toPath());

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            var dalekSigner = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            cryptoSuite = dalekSigner;

            // avoid generating files, only to overwrite them right after
            if (!command.shouldGenerateNextVerifyingKeyPem) {
                storeKeysOnDisk(dalekSigner, command.forceOverwrite);
            }
        }

        if (command.shouldGenerateNextVerifyingKeyPem) {
            generateAndSaveNewKey(command.forceOverwrite, command.nextVerifyingKeyPemFiles);
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextKeyPemFiles = command.nextVerifyingKeyPemFiles;

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(DidLogCreatorContext.builder(didMethod, cryptoSuite)
                .assertionMethods(assertionMethods)
                .authentications(authentications)
                // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                // Instead of calling deprecated .nextKeys(nextKeyPemFiles)
                .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextKeyPemFiles))
                .build()
                .create(identifierRegistryUrl));
    }

    @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.NPathComplexity"})
    void runUpdateDidLogCommand(UpdateDidLogCommand command) throws CommandException, VerificationMethodException, IOException, DidLogCreatorStrategyException, VcDataIntegrityCryptographicSuiteException, UpdateKeysDidMethodParameterException, NextKeyHashesDidMethodParameterException, DidLogUpdaterStrategyException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return;
        }

        var didLogFile = command.didLogFile;

        var didLogMeta = fetchDidLogMeta(didLogFile);

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
            throw new CommandException("No update will take place as no verification material is supplied whatsoever");
        }

        if (command.shouldGenerateNextVerifyingKeyPem || command.shouldGenerateVerifyingKeyPem) {
            if (command.shouldGenerateNextVerifyingKeyPem && command.shouldGenerateVerifyingKeyPem) {
                throw new ParameterException("Not allowed to use the both flags ('%s', '%s' together".formatted(PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY, PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY));
            }

            if (command.shouldGenerateNextVerifyingKeyPem) {
                generateAndSaveNewKey(command.forceOverwrite, command.nextVerifyingKeyPemFiles);
            } else {
                generateAndSaveNewKey(command.forceOverwrite, command.verifyingKeyPemFiles);
            }
        }

        var verifyingKeyPemFiles = command.verifyingKeyPemFiles;
        var nextVerifyingKeyPemFiles = command.nextVerifyingKeyPemFiles; // if set, denotes key pre-rotation

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            throw new CommandException("Incomplete source of the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
            throw new CommandException("Illegal signing (private) ed25519 key supplied");
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogUpdaterContext.builder(didLogMeta.getParams().getDidMethodEnum(), cryptoSuite)
                        .assertionMethods(assertionMethods)
                        .authentications(authentications)
                        // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                        .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                        // Instead of calling deprecated .nextKeys(nextVerifyingKeyPemFiles)
                        .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextVerifyingKeyPemFiles))
                        .build()
                        .update(didLogFile));
    }

    void runDeactivateDidLogCommand(DeactivateDidLogCommand command) throws CommandException, VcDataIntegrityCryptographicSuiteException, IOException, DidLogDeactivatorStrategyException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return;
        }

        var didLogFile = command.didLogFile;
        var didLogMeta = fetchDidLogMeta(didLogFile);

        VcDataIntegrityCryptographicSuite cryptoSuite = getCryptoGraphicSuite(command);
        if (cryptoSuite == null) {
            throw new CommandException("No valid source of signing/verifying ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorContext.builder(didLogMeta.getParams().getDidMethodEnum(), cryptoSuite)
                        .build()
                        .deactivate(didLogFile));
    }

    void runPoPCreateCommand(CreateProofOfPossessionCommand command) throws IOException, ProofOfPossessionCreatorException, CommandException, UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, JOSEException, KeyException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return;
        }

        // Duration after which the JWT expires
        Duration validDuration = Duration.ofDays(1);

        var nonce = command.nonce;
        var didLogFile = command.didLog;
        var kid = command.kid;

        var didLog = Files.readString(didLogFile.toPath());

        ProofOfPossessionJWSSigner signer = null;
        if (command.signingKeyPemFile != null) {
            signer = new EcP256ProofOfPossessionJWSSigner(command.signingKeyPemFile.toPath(), kid);
        } else if (command.securosysPrimusKeyStoreLoader != null && command.primusKeyAlias != null) {
            signer = HsmProofOfPossessionJWSSigner.newPrimusSigner(command.securosysPrimusKeyStoreLoader, command.primusKeyAlias, command.primusKeyPassword, kid);
        }

        if (signer == null) {
            throw new CommandException("No valid source of signing EC P-256 key supplied. Use one of the relevant options to supply keys");
        }

        var proof = new ProofOfPossessionCreator(signer).create(nonce, validDuration);
        try {
            var verifier = new ProofOfPossessionVerifier(didLog);
            verifier.verify(proof, nonce);
        } catch (ProofOfPossessionVerifierException e) {
            throw new CommandException("Failed to verify generated proof: %s".formatted(e.getLocalizedMessage()), e);
        }

        jc.getConsole().println(proof.serialize());
    }

    void runPoPVerifyCommand(VerifyProofOfPossessionCommand command) throws IOException, CommandException {
        if (command.help) {
            jc.usage(parsedCommandName);
            return;
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
            throw new CommandException("Provided JWT is invalid: " + e.getLocalizedMessage(), e);
        }
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
            } catch (UnrecoverableEntryException | KeyStoreException | NoSuchAlgorithmException | KeyException e) {
                throw new VcDataIntegrityCryptographicSuiteException("Failed to initialize primus:" + e.getMessage(), e);
            }
        }
        return null;
    }

    /**
     *
     * @param forceOverwrite
     * @param target
     * @throws FileAlreadyExistsException if it fails to create or overwrite the file
     */
    void generateAndSaveNewKey(boolean forceOverwrite, Set<File> target) throws IOException, CommandException {
        FilesPrivacy.createPrivateKeyDirectoryIfDoesNotExist(getOutputDir().toPath());
        var dalekSigner = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        storeKeysOnDisk(dalekSigner, forceOverwrite);
        target.add(getPublicKeyFile());
    }

    /**
     * Stores the public and private key of the cryptoSuite on the local file system in ```.didtoolbox``` directory.
    *
     * @param cryptoSuite of the keypair to be stored
     * @param forceOverwrite allows to overwrite already existing key files
     * @throws FileAlreadyExistsException
     */
    @SuppressWarnings("PMD.CognitiveComplexity")
    void storeKeysOnDisk(EdDsaJcs2022VcDataIntegrityCryptographicSuite cryptoSuite, boolean forceOverwrite) throws CommandException, FileAlreadyExistsException {
        var outputDir = getOutputDir();
        if (!outputDir.exists() || forceOverwrite) {
            try {
                FilesPrivacy.createPrivateDirectory(outputDir.toPath(), forceOverwrite); // may throw FileAlreadyExistsException, SecurityException etc.
            } catch (DirectoryNotEmptyException | FileAlreadyExistsException ex) {
                if (!outputDir.exists()) {
                    throw new IllegalArgumentException(ex); // the delete-create logic is not implemented properly
                }
                // ignore otherwise
            } catch (AccessDeniedException ex) {
                throw new CommandException("Access denied to " + outputDir.getPath() + " due to: " + ex.getMessage(), ex);
            } catch (Throwable thr) {
                throw new CommandException("Failed to (re)create " + outputDir.getPath() + " directory due to: " + thr.getMessage(), thr);
            }
        }

        var privateKeyFile = getPrivateKeyFile();
        if (privateKeyFile.exists() && !forceOverwrite) {
            throw new CommandException("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + privateKeyFile.getPath());
        }

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
            throw new CommandException("Access denied to private key PEM file " + privateKeyFile.getPath() + " due to: " + ex.getMessage(), ex);
        } catch (Throwable thr) {
            throw new CommandException("The private key PEM file could not be created with restricted access: " + privateKeyFile.getPath(), thr);
        }

        try {
            cryptoSuite.writePkcs8PemFile(privateKeyFile.toPath());
            cryptoSuite.writePublicKeyPemFile(getPublicKeyFile().toPath());
        } catch (VcDataIntegrityCryptographicSuiteException ex) {
            throw new CommandException("Failed to persist PEM file(s) due to: " + ex.getMessage(), ex);
        }
    }

    // add base path to constructor or something, ta make it easier for tests.
    private File getOutputDir() {
        return new File(this.basePath);
    }

    private File getPrivateKeyFile() {
        return new File(getOutputDir(), "id_ed25519");
    }

    private File getPublicKeyFile() {
        return new File(getOutputDir(), "id_ed25519.pub");
    }

    @SuppressWarnings("PMD.MissingSerialVersionUID")
    public static class CommandException extends Exception {
        CommandException(String message, Throwable cause) {
            super(message, cause);
        }

        CommandException(String message) {
            super(message);
        }
    }
}