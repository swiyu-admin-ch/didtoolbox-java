package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.context.*;
import ch.admin.bj.swiyu.didtoolbox.jcommander.*;
import ch.admin.bj.swiyu.didtoolbox.model.*;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519ProofOfPossessionJWSSignerImpl;
import ch.admin.bj.swiyu.didtoolbox.securosys.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Ed25519VerifyingKey;
import com.beust.jcommander.JCommander;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * The class is introduced for the sake of being able to test the CLI with no hassle involved.
 */
@SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.DoNotTerminateVM"})
final class JCommanderRunner {

    private final JCommander jc;
    private final String parsedCommandName;

    JCommanderRunner(JCommander jc, String parsedCommandName) {
        this.jc = jc;
        this.parsedCommandName = parsedCommandName;
    }

    @SuppressWarnings({"PMD.NPathComplexity", "PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.AvoidInstantiatingObjectsInLoops", "PMD.UseConcurrentHashMap"})
    void runCreateDidLogCommand(CreateDidLogCommand command)
            throws UnrecoverableEntryException, KeyStoreException, NoSuchAlgorithmException, KeyException, IOException,
            VcDataIntegrityCryptographicSuiteException, DidLogCreatorStrategyException, NextKeyHashesDidMethodParameterException, UpdateKeysDidMethodParameterException {
        if (command.help) {
            jc.usage(parsedCommandName);
            System.exit(0);
        }

        URL identifierRegistryUrl = command.identifierRegistryUrl;

        var didMethod = command.methodVersion; // may return null
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
        var nextKeyPemFiles = command.nextVerifyingKeyPemFiles;

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        boolean forceOverwrite = command.forceOverwrite;

        VcDataIntegrityCryptographicSuite cryptoSuite = null;

        if (signingKeyPemFile != null && verifyingKeyPemFiles == null) {

            overAndOut(jc, parsedCommandName, "No matching verifying (public) ed25519 key supplied");

        } else if (signingKeyPemFile != null) { // at this point, verifyingKeyPemFiles must be non-null already

            File verifyingKeyPemFile = null;
            for (var pemFile : verifyingKeyPemFiles) {
                try {
                    cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile.toPath()); // supplied external key (pair)
                    if (Ed25519VerifyingKey.Companion.readPublicKeyPemFile(pemFile.getPath()).toMultibase()
                            .equals(cryptoSuite.getVerificationKeyMultibase())) {
                        // At this point, the matching verifying key is detected, so we are free to break from the loop
                        verifyingKeyPemFile = pemFile;
                        break;
                    }
                } catch (VcDataIntegrityCryptographicSuiteException | DidSidekicksException ignoreMalformedPemFiles) {
                }
            }

            if (verifyingKeyPemFile == null) {
                overAndOut(jc, parsedCommandName, "No matching verifying (public) ed25519 key supplied");
            }

        } else if (jksFile != null && jksAlias != null) {

            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Files.newInputStream(jksFile.toPath()), jksPassword, jksAlias, jksPassword); // supplied external key pair

        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

            cryptoSuite = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

        } else {

            var dalekSigner = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
            cryptoSuite = dalekSigner;

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
                        throw new IllegalArgumentException(ex); // the delete-create logic is not implemented properly
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
                    throw new IllegalArgumentException(ex); // it should be a file, not a directory
                } catch (FileAlreadyExistsException ex) {
                    if (!privateKeyFile.exists()) {
                        throw new IllegalArgumentException(ex);
                    }
                    throw ex;
                } catch (AccessDeniedException ex) {
                    overAndOut(jc, parsedCommandName, "Access denied to private key PEM file " + privateKeyFile.getPath() + " due to: " + ex.getMessage());
                } catch (Throwable thr) {
                    overAndOut(jc, parsedCommandName, "The private key PEM file could not be created with restricted access: " + privateKeyFile.getPath());
                }

                try {
                    dalekSigner.writePkcs8PemFile(privateKeyFile.toPath());
                    dalekSigner.writePublicKeyPemFile(new File(outputDir, privateKeyFile.getName() + ".pub").toPath());
                } catch (VcDataIntegrityCryptographicSuiteException ex) {
                    overAndOut(jc, parsedCommandName, "Failed to persist PEM file(s) due to: " + ex.getMessage());
                }

            } else {
                overAndOut(jc, parsedCommandName, "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: " + privateKeyFile.getPath());
            }
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(DidLogCreatorContext.builder()
                .didMethod(didMethod)
                .cryptographicSuite(cryptoSuite)
                .assertionMethodKeys(assertionMethodKeysMap)
                .authenticationKeys(authenticationKeysMap)
                // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                // Instead of calling deprecated .nextKeys(nextKeyPemFiles)
                .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextKeyPemFiles))
                .forceOverwrite(forceOverwrite)
                .build()
                .create(identifierRegistryUrl));
    }

    @SuppressWarnings({"PMD.NPathComplexity", "PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.AvoidInstantiatingObjectsInLoops", "PMD.UseConcurrentHashMap"})
    void runUpdateDidLogCommand(UpdateDidLogCommand command)
            throws IOException, UnrecoverableEntryException, VcDataIntegrityCryptographicSuiteException, KeyStoreException,
            NoSuchAlgorithmException, KeyException, DidLogUpdaterStrategyException, NextKeyHashesDidMethodParameterException, UpdateKeysDidMethodParameterException {
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
        var nextVerifyingKeyPemFiles = command.nextVerifyingKeyPemFiles; // if set, denotes key pre-rotation

        var jksFile = command.jksFile;
        var jksPassword = command.jksPassword;
        var jksAlias = command.jksAlias;

        var primus = command.securosysPrimusKeyStoreLoader;
        var primusKeyAlias = command.primusKeyAlias;
        var primusKeyPassword = command.primusKeyPassword;

        VcDataIntegrityCryptographicSuite cryptoSuite = null; // no default, must be supplied

        if (signingKeyPemFile != null && verifyingKeyPemFiles != null) {

            String matchingUpdateKey = null;

            if (didLogMeta.isKeyPreRotationActivated()) {

                for (var pemFile : verifyingKeyPemFiles) {
                    try {
                        var multikey = PemUtils.readEd25519PublicKeyPemFileToMultibase(pemFile.toPath());
                        // Only pre-rotation keys are relevant here
                        if (didLogMeta.isPreRotatedUpdateKey(multikey)) {
                            // the signing key is supplied externally, but verifying key should be already among updateKeys
                            cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile.toPath());
                            if (multikey.equals(cryptoSuite.getVerificationKeyMultibase())) {
                                // At this point, the matching verifying key is detected, so we are free to break from the loop
                                matchingUpdateKey = multikey;
                                break;
                            }
                        }
                    } catch (VcDataIntegrityCryptographicSuiteException |
                             DidSidekicksException ignoreMalformedPemFiles) {
                    }
                }

            } else {

                for (var pemFile : verifyingKeyPemFiles) {
                    try {
                        var publicKeyEd25519Multibase = PemUtils.readEd25519PublicKeyPemFileToMultibase(pemFile.toPath());
                        // the signing key is supplied externally, but verifying key should be already among updateKeys
                        cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile.toPath());
                        if (publicKeyEd25519Multibase.equals(cryptoSuite.getVerificationKeyMultibase())) {
                            // At this point, the matching verifying key is detected, so we are free to break from the loop
                            matchingUpdateKey = publicKeyEd25519Multibase;
                            break;
                        }
                    } catch (VcDataIntegrityCryptographicSuiteException |
                             DidSidekicksException ignoreMalformedPemFiles) {
                    }
                }

                if (matchingUpdateKey == null) {
                    overAndOut(jc, parsedCommandName, "No valid matching verifying (public) ed25519 key supplied");
                }

                for (var publicKeyEd25519Multibase : didLogMeta.getParams().getUpdateKeys()) {
                    try {
                        // the signing key is supplied externally, but verifying key should be already among updateKeys
                        cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile.toPath());
                        if (publicKeyEd25519Multibase.equals(cryptoSuite.getVerificationKeyMultibase())) {
                            // At this point, the matching verifying key is detected, so we are free to break from the loop
                            matchingUpdateKey = publicKeyEd25519Multibase;
                            break;
                        }
                    } catch (VcDataIntegrityCryptographicSuiteException ignoreMalformedPemFiles) {
                    }
                }
            }

            if (matchingUpdateKey == null) {
                overAndOut(jc, parsedCommandName, "No matching signing (private) ed25519 key supplied");
            }

        } else if (jksFile != null && jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Files.newInputStream(jksFile.toPath()), jksPassword, jksAlias, jksPassword); // supplied external key pair

            if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
                overAndOut(jc, parsedCommandName, "Illegal signing (private) ed25519 key supplied");
            }

        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

            cryptoSuite = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

            if (didLogMeta.isKeyPreRotationActivated() && !didLogMeta.isPreRotatedUpdateKey(cryptoSuite.getVerificationKeyMultibase())) {
                overAndOut(jc, parsedCommandName, "Illegal signing (private) ed25519 key supplied");
            }

        } else {
            overAndOut(jc, parsedCommandName, "Incomplete source of the (signing/verifying) ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        // CAUTION At this point, the methodVersion var of type DidMethodEnum MUST be non-null already
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogUpdaterContext.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .cryptographicSuite(cryptoSuite)
                        .assertionMethodKeys(assertionMethodKeysMap)
                        .authenticationKeys(authenticationKeysMap)
                        // Instead of calling deprecated .updateKeys(verifyingKeyPemFiles)
                        .updateKeysDidMethodParameter(UpdateKeysDidMethodParameter.of(verifyingKeyPemFiles))
                        // Instead of calling deprecated .nextKeys(nextVerifyingKeyPemFiles)
                        .nextKeyHashesDidMethodParameter(NextKeyHashesDidMethodParameter.of(nextVerifyingKeyPemFiles))
                        .build()
                        .update(didLogFile));
    }

    @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.AvoidInstantiatingObjectsInLoops"})
    void runDeactivateDidLogCommand(DeactivateDidLogCommand command)
            throws IOException, UnrecoverableEntryException, VcDataIntegrityCryptographicSuiteException, KeyStoreException,
            NoSuchAlgorithmException, KeyException, DidLogDeactivatorStrategyException {
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

        VcDataIntegrityCryptographicSuite cryptoSuite = null; // no default, must be supplied

        if (signingKeyPemFile != null) {

            String matchingUpdateKey = null;
            // CAUTION In case the supplied DID log have already been deactivated (i.e. "parameters":{"deactivated":true,"updateKeys":[]}),
            //         the updateKeys collection would be null
            if (didLogMeta.getParams().getUpdateKeys() != null) {
                for (var publicKeyEd25519Multibase : didLogMeta.getParams().getUpdateKeys()) {
                    try {
                        // the signing key is supplied externally, but verifying key should be already among updateKeys
                        cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(signingKeyPemFile.toPath());
                        if (publicKeyEd25519Multibase.equals(cryptoSuite.getVerificationKeyMultibase())) {
                            // At this point, the matching verifying key is detected, so we are free to break from the loop
                            matchingUpdateKey = publicKeyEd25519Multibase;
                            break;
                        }
                    } catch (VcDataIntegrityCryptographicSuiteException ignoreMalformedPemFiles) {
                    }
                }

                if (matchingUpdateKey == null) {
                    overAndOut(jc, parsedCommandName, "No valid matching signing key supplied");
                }
            }

        } else if (jksFile != null && jksPassword != null && jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(Files.newInputStream(jksFile.toPath()), jksPassword, jksAlias, jksPassword); // supplied external key pair

        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {

            cryptoSuite = new PrimusEd25519VerificationMethodKeyProviderImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair

        } else {
            overAndOut(jc, parsedCommandName, "No valid source of signing/verifying ed25519 keys supplied. Use one of the relevant options to supply keys");
        }

        // CAUTION Trimming the existing DID log prevents ending up having multiple line separators in between (after appending the new entry)
        jc.getConsole().println(Files.readString(didLogFile.toPath()).trim() + System.lineSeparator() +
                DidLogDeactivatorContext.builder()
                        .didMethod(didLogMeta.getParams().getDidMethodEnum())
                        //.didMethod(DidMethodEnum.detectDidMethod(didLogFile)) // No need to parse the DID log twice
                        .cryptographicSuite(cryptoSuite)
                        .build()
                        .deactivate(didLogFile));
    }

    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    void runPoPCreateCommand(CreateProofOfPossessionCommand command)
            throws IOException, UnrecoverableEntryException, VcDataIntegrityCryptographicSuiteException, KeyStoreException,
            NoSuchAlgorithmException, KeyException, ProofOfPossessionCreatorException {
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

        } else if (signingKeyPemFile != null) {

            try {
                signer = new EdDsaJcs2022ProofOfPossessionJWSSigner(signingKeyPemFile.toPath()); // supplied external key pair
            } catch (VcDataIntegrityCryptographicSuiteException ex) {
                overAndOut(jc, parsedCommandName, "Failed to load the supplied ed25519 key (pair): " + ex.getLocalizedMessage());
            }

        } else if (jksFile != null && jksAlias != null) {
            // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
            signer = new EdDsaJcs2022ProofOfPossessionJWSSigner(Files.newInputStream(jksFile.toPath()), jksPassword, jksAlias, jksPassword); // supplied external key pair
        } else if (primus != null && primusKeyAlias != null) { // && primusKeyPassword != null) {
            signer = new PrimusEd25519ProofOfPossessionJWSSignerImpl(primus, primusKeyAlias, primusKeyPassword); // supplied external key pair
        } else {
            overAndOut(jc, parsedCommandName, "No source for the (signing) ed25519 key supplied. Use one of the relevant options to supply keys");
        }

        var proof = new ProofOfPossessionCreator(signer)
                .create(nonce, validDuration);

        jc.getConsole().println(proof.serialize());
    }

    void runPoPVerifyCommand(VerifyProofOfPossessionCommand command) throws IOException {
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
            jc.getConsole().println("Provided JWT is valid.");
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
                overAndOut(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
            }
        } catch (IOException exc) { // not a did:tdw log
            overAndOut(jc, parsedCommandName, "The supplied file contains unsupported DID log format: " + didLogFile.getName());
        }

        if (didLogMeta == null ||
                didLogMeta.getParams() == null ||
                didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new IllegalArgumentException("Incomplete metadata");
        }

        return didLogMeta;
    }
}