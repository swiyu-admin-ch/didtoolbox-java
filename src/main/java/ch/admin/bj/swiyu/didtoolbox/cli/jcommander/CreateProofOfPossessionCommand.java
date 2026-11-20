package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.PemFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.converter.PrimusCredentialsFileParameterConverter;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.PemFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.PrimusCredentialsFileParameterValidator;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.KeyMaterialLoader;
import ch.admin.bj.swiyu.didtoolbox.cli.keymaterial.KeyMaterialLoaderFactory;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreatorException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifier;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.nimbusds.jose.JOSEException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.Optional;

@Parameters(
        commandNames = {CreateProofOfPossessionCommand.COMMAND_NAME},
        commandDescription = "Create a proof of possession JWT signed with the provided private key that expires after 24 hours. ",
        parametersValidators = {CommandParametersValidator.class}
)
public class CreateProofOfPossessionCommand extends CommandBase {
    final public static String COMMAND_NAME = "create-pop";

    // Duration after which the JWT expires
    private static final Duration VALID_DURATION = Duration.ofDays(1);

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_NONCE, CommandParameterNames.PARAM_NAME_SHORT_NONCE},
            description = "Possession which will be proven by the JWT.",
            required = true)
    public String nonce;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_DID_LOG_FILE, CommandParameterNames.PARAM_NAME_SHORT_DID_LOG_FILE},
            description = "The file containing the kid used to sign the proof.",
            required = true)
    public File didLog;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_KID, CommandParameterNames.PARAM_NAME_SHORT_KID},
            description = "KID of the key within the DID log to use.",
            required = true)
    public String kid;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_SIGNING_KEY_FILE, CommandParameterNames.PARAM_NAME_SHORT_SIGNING_KEY_FILE},
            description = "A P-256 private key file matching the specified key within the DID log",
            converter = PemFileParameterConverter.class,
            validateWith = PemFileParameterValidator.class,
            required = false)
    public File signingKeyPemFile;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_CREDENTIALS, CommandParameterNames.PARAM_NAME_SHORT_PRIMUS_CREDENTIALS},
            description = "A safely stored credentials file required when using private keys available in the Securosys Primus (HSM) Keystore. " +
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
        description = "An alias the key pair (stored in the Securosys Primus (HSM) Keystore) is associated with. " +
            "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)")
    public String primusKeyAlias;

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD},
            description = "An optional password required for recovering the key pair (stored in Securosys Primus (HSM) Keystore). " +
                    "This CLI parameter should always be used exclusively alongside all the other --primus-* CLI parameters, related to Securosys Primus (HSM)",
            password = true)
    public String primusKeyPassword;

    /**
     * Selects the source of the signing key supplied via CLI parameters (a Java KeyStore is not supported here).
     * <p>
     * The first complete key source wins, as the mutual exclusivity of the key sources is enforced at parse time by
     * {@link CommandParametersValidator}.
     *
     * @return the matching loader, or {@link Optional#empty()} if no (complete) key source is supplied
     */
    public Optional<KeyMaterialLoader> keyMaterialLoader() {
        return KeyMaterialLoaderFactory.pem(signingKeyPemFile)
                .or(() -> KeyMaterialLoaderFactory.primus(securosysPrimusKeyStoreLoader, primusKeyAlias, primusKeyPassword));
    }

    @Override
    protected void execute(CommandContext context) throws IOException, ProofOfPossessionCreatorException, CommandException, GeneralSecurityException, JOSEException, VcDataIntegrityCryptographicSuiteException {
        var didLogContent = Files.readString(didLog.toPath());

        var signer = keyMaterialLoader()
                .orElseThrow(() -> new CommandException("No valid source of signing P-256 key supplied. Use one of the relevant options to supply keys"))
                .loadProofOfPossessionSigner(kid);

        var proof = new ProofOfPossessionCreator(signer).create(nonce, VALID_DURATION);
        try {
            var verifier = new ProofOfPossessionVerifier(didLogContent);
            verifier.verify(proof, nonce);
        } catch (ProofOfPossessionVerifierException e) {
            throw new CommandException("Failed to verify generated proof: %s".formatted(e.getLocalizedMessage()), e);
        }

        context.println(proof.serialize());
    }
}
