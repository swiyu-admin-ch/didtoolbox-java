package ch.admin.bj.swiyu.didtoolbox.jcommander;

/**
 * The home for all CLI parameter names, both short and long.
 */
public interface CommandParameterNames {

    String PARAM_NAME_LONG_SIGNING_KEY_FILE = "--signing-key-file";
    String PARAM_NAME_SHORT_SIGNING_KEY_FILE = "-s";

    String PARAM_NAME_LONG_JKS_FILE = "--jks-file";
    String PARAM_NAME_SHORT_JKS_FILE = "-j";
    String PARAM_NAME_LONG_JKS_PASSWORD = "--jks-password";
    String PARAM_NAME_LONG_JKS_ALIAS = "--jks-alias";

    String PARAM_NAME_LONG_PRIMUS_CREDENTIALS = "--primus-credentials";
    String PARAM_NAME_SHORT_PRIMUS_CREDENTIALS = "-p";
    String PARAM_NAME_LONG_PRIMUS_KEYSTORE_ALIAS = "--primus-keystore-alias";
    String PARAM_NAME_SHORT_PRIMUS_KEYSTORE_ALIAS = "-q";
    String PARAM_NAME_LONG_PRIMUS_KEYSTORE_PASSWORD = "--primus-keystore-password";
}
