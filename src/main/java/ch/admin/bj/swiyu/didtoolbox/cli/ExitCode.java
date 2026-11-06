package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreInitializationException;
import com.beust.jcommander.ParameterException;

import java.io.IOException;
import java.security.KeyStoreException;

/**
 * Exit codes returned by the CLI.
 */
public enum ExitCode {
    /**
     * The command completed successfully.
     */
    SUCCESS(0),
    /**
     * An unexpected (internal) error occurred.
     */
    UNEXPECTED(1),
    /**
     * Invalid usage, e.g. unknown command, invalid or missing parameters.
     */
    USAGE(2),
    /**
     * I/O or environment error, e.g. missing/unreadable file, access denied, HSM unreachable.
     */
    IO_ENVIRONMENT(3),
    /**
     * Cryptographic or verification error, e.g. invalid proof of possession or DID log.
     */
    CRYPTO_VERIFICATION(4);

    private final int code;

    ExitCode(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    static ExitCode of(Throwable throwable) {
        for (var t = throwable; t != null; t = t.getCause()) {
            if (t instanceof IOException || t instanceof KeyStoreException || t instanceof PrimusKeyStoreInitializationException) {
                return IO_ENVIRONMENT;
            }
        }
        if (throwable instanceof ParameterException
                || (throwable instanceof JCommanderRunner.CommandException && throwable.getCause() == null)) {
            return USAGE;
        }
        if (throwable instanceof RuntimeException || throwable instanceof Error) {
            return UNEXPECTED;
        }
        return CRYPTO_VERIFICATION;
    }
}
