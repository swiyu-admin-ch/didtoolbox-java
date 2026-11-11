package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.JksFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.PemFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.PrimusCredentialsFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.JksFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.PrimusCredentialsFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.KeyMaterialLoader;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.KeyMaterialLoaderFactory;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMeta;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDidLogMetaPeeker;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDidLogMetaPeeker;
import com.beust.jcommander.Parameter;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Optional;

/**
 * The base class for all Command classes in the package that focus on DID logs.
 */
public abstract class DidLogCommandBase extends CommandBase {

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE},
            description = "The ed25519 private key file required for signing a DID log entry or a PoP JWT. In PEM Format. " +
                    "This CLI parameter cannot be used in conjunction with any of --jks-* or --primus-* CLI parameters",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class)
    public File signingKeyPemFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_FILE, CommandParameterNames.PARAM_NAME_SHORT_JKS_FILE},
            description = "Java KeyStore (PKCS12) file to read the (signing/verifying) keys from. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            converter = JksFileParameterConverter.class,
            validateWith = JksFileParameterValidator.class)
    public File jksFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_PASSWORD},
            description = "Java KeyStore password used to check the integrity of the keystore, the password used to unlock the keystore. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters",
            password = true)
    public String jksPassword;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_JKS_ALIAS},
            description = "Java KeyStore alias name of the entry to process. " +
                    "This CLI parameter should always be used exclusively alongside all the other --jks-* CLI parameters")
    public String jksAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS},
            description = "A safely stored credentials file required when using (signing/verifying) keys available in the Securosys Primus (HSM) Keystore. " +
                    "It should feature a quartet of the following properties: " +
                    "securosys_primus_host, securosys_primus_port, securosys_primus_user and securosys_primus_password. " +
                    "Any credential missing in this file will simply fallback to its system environment counterpart (if set) - the relevant envvars in this case are: " +
                    "SECUROSYS_PRIMUS_HOST, SECUROSYS_PRIMUS_PORT, SECUROSYS_PRIMUS_USER and SECUROSYS_PRIMUS_PASSWORD. " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            converter = PrimusCredentialsFileParameterConverter.class,
            validateWith = PrimusCredentialsFileParameterValidator.class
    )
    public PrimusKeyStoreLoader securosysPrimusKeyStoreLoader;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS},
            description = "An alias the (signing/verifying) key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)")
    public String primusKeyAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD},
            description = "An optional password required for recovering the (signing/verifying) key pair (stored in Securosys Primus (HSM) Keystore). " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            password = true)
    public String primusKeyPassword;

    /**
     * Selects the source of the (signing/verifying) key material supplied via CLI parameters.
     * <p>
     * The first complete key source wins, as the mutual exclusivity of the key sources is enforced at parse time by
     * {@link ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator}.
     *
     * @return the matching loader, or {@link Optional#empty()} if no (complete) key source is supplied
     */
    public Optional<KeyMaterialLoader> keyMaterialLoader() {
        return KeyMaterialLoaderFactory.pem(signingKeyPemFile)
                .or(() -> KeyMaterialLoaderFactory.jks(jksFile, jksPassword, jksAlias))
                .or(() -> KeyMaterialLoaderFactory.primus(securosysPrimusKeyStoreLoader, primusKeyAlias, primusKeyPassword));
    }

    /**
     * Simple helper for extracting DID method parameters in a specification-agnostic fashion.
     *
     * @param didLogFile {@code File} object containing a valid DID log
     * @return a {@code DidLogMeta} object, never {@code null}
     */
    static DidLogMeta fetchDidLogMeta(File didLogFile) throws CommandException {
        String didLog;
        try {
            didLog = Files.readString(didLogFile.toPath());
        } catch (IOException exc) {
            throw new CommandException("Failed to read the supplied DID log file: " + didLogFile.getName(), exc);
        }

        DidLogMeta didLogMeta;
        try {
            didLogMeta = TdwDidLogMetaPeeker.peek(didLog); // assume a did:tdw log
        } catch (DidLogMetaPeekerException exc) { // not a did:tdw log
            try {
                didLogMeta = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog); // assume a did:webvh log
            } catch (DidLogMetaPeekerException exc1) { // not a did:webvh log
                throw new CommandException("The supplied file contains unsupported DID log format: " + didLogFile.getName(), exc1); // NOPMD PreserveStackTrace: false positive
            }
        }

        if (didLogMeta.getParams() == null ||
                didLogMeta.getParams().getDidMethodEnum() == null) {
            throw new CommandException("The supplied DID log features incomplete metadata: " + didLogFile.getName());
        }

        return didLogMeta;
    }
}
