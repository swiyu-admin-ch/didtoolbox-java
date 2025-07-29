package ch.admin.bj.swiyu.didtoolbox.jcommander;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.nimbusds.jwt.SignedJWT;

import java.io.File;

@Parameters(
        commandNames = {VerifyProofOfPossessionCommand.COMMAND_NAME} ,
        commandDescription = "Verifies the validity of the provided proof of possession with the provided DID log."
)
public class VerifyProofOfPossessionCommand {

    final public static String COMMAND_NAME = "verify-pop";

    @Parameter(names = {CommandParameterNames.PARAM_NAME_LONG_USAGE, CommandParameterNames.PARAM_NAME_SHORT_USAGE},
            description = "Display help for the DID toolbox command",
            help = true)
    public boolean help;

    @Parameter(names = { "--proof-of-possession", "--nonce", "-n"},
            description = "Text representation of the possession to be included in the proof",
            required = true)
    public String nonce;

    @Parameter(names = {"--did-log-file", "-d"},
            description = "The file containing a valid did:tdw DID log of the owner.",
            converter = DidLogFileParameterConverter.class,
            validateWith = DidLogFileParameterValidator.class,
            required = true)
    public File didLogFile;

    @Parameter(names = {"--jwt", "-j"},
            description = "JWT to be verified",
            converter = JWTParameterConverter.class,
            validateWith = JWTParameterValidator.class,
            required = true)
    public SignedJWT jwt;
}
