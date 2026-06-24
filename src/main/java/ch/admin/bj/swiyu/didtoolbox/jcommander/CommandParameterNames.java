package ch.admin.bj.swiyu.didtoolbox.jcommander;

/**
 * The home for all CLI parameter names, both short and long.
 */
@SuppressWarnings({"PMD.ConstantsInInterface"})
public interface CommandParameterNames {
    public String PARAM_NAME_LONG_USAGE = "--help";
    public String PARAM_NAME_SHORT_USAGE = "-h";

    public String PARAM_NAME_LONG_SIGNING_KEY_FILE = "--signing-key-file";
    public String PARAM_NAME_SHORT_SIGNING_KEY_FILE = "-s";

    public String PARAM_NAME_LONG_JKS_FILE = "--jks-file";
    public String PARAM_NAME_SHORT_JKS_FILE = "-j";
    public String PARAM_NAME_LONG_JKS_PASSWORD = "--jks-password";
    public String PARAM_NAME_LONG_JKS_ALIAS = "--jks-alias";

    public String PARAM_NAME_LONG_PRIMUS_CREDENTIALS = "--primus-credentials";
    public String PARAM_NAME_SHORT_PRIMUS_CREDENTIALS = "-p";
    public String PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS = "--primus-keystore-alias";
    public String PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS = "-q";
    public String PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD = "--primus-keystore-password";

    public String PARAM_NAME_LONG_VERIFYING_KEY_FILES = "--verifying-key-files";
    public String PARAM_NAME_SHORT_VERIFYING_KEY_FILES = "-v";

    public String PARAM_NAME_LONG_GENERATE_NEW_VERIFYING_KEY = "--generate-new-verifying-key";
    public String PARAM_NAME_SHORT_GENERATE_NEW_VERIFYING_KEY = "-gv";

    @Deprecated(since = "1.4.1")
    public String PARAM_NAME_LONG_VERIFYING_KEY_FILE = "--verifying-key-file";
    @Deprecated(since = "1.4.1")
    public String PARAM_NAME_SHORT_VERIFYING_KEY_FILE = "-v";

    public String PARAM_NAME_LONG_NEXT_VERIFYING_KEY_FILES = "--verifying-key-files-next";
    public String PARAM_NAME_SHORT_NEXT_VERIFYING_KEY_FILES = "-w";

    public String PARAM_NAME_LONG_GENERATE_NEXT_VERIFYING_KEY = "--generate-next-verifying-key";
    public String PARAM_NAME_SHORT_GENERATE_NEXT_VERIFYING_KEY = "-gw";

    public String PARAM_NAME_LONG_ASSERTION_METHOD_KEYS = "--assert";
    public String PARAM_NAME_SHORT_ASSERTION_METHOD_KEYS = "-a";

    public String PARAM_NAME_LONG_AUTHENTICATION_METHOD_KEYS = "--auth";
    public String PARAM_NAME_SHORT_AUTHENTICATION_METHOD_KEYS = "-t";

    public String PARAM_NAME_LONG_DID_LOG_FILE = "--did-log-file";
    public String PARAM_NAME_SHORT_DID_LOG_FILE = "-d";

    public String PARAM_NAME_LONG_KID = "--kid";
    public String PARAM_NAME_SHORT_KID = "-k";

    public String PARAM_NAME_LONG_NONCE = "--nonce";
    public String PARAM_NAME_SHORT_NONCE = "-n";

    public String PARAM_NAME_LONG_JWT = "--jwt";
    public String PARAM_NAME_SHORT_JWT = "-j";
}
