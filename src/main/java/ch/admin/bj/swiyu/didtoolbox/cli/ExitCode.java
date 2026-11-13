package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import ch.admin.bj.swiyu.didtoolbox.did.InvalidDidLogException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogDeactivatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.context.DidLogUpdaterStrategyException;
import ch.admin.bj.swiyu.didtoolbox.did.model.NextKeyHashesDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.UpdateKeysDidMethodParameterException;
import ch.admin.bj.swiyu.didtoolbox.did.model.VerificationMethodException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionCreatorException;
import ch.admin.bj.swiyu.didtoolbox.pop.ProofOfPossessionVerifierException;
import com.beust.jcommander.ParameterException;
import com.nimbusds.jose.JOSEException;

import java.io.IOException;
import java.security.GeneralSecurityException;
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
     * Cryptographic, verification or DID log error, e.g. invalid proof of possession, malformed key or DID log, already deactivated DID.
     */
    CRYPTO_VERIFICATION(4);

    private final int value;

    ExitCode(int value) {
        this.value = value;
    }

    public int code() {
        return value;
    }

    @SuppressWarnings("PMD.CyclomaticComplexity")
    static ExitCode of(Throwable throwable) {
        for (var t = throwable; t != null; t = t.getCause()) {
            if (t instanceof IOException || t instanceof KeyStoreException || t instanceof PrimusKeyStoreInitializationException) {
                return IO_ENVIRONMENT;
            }
        }
        for (var t = throwable; t != null; t = t.getCause()) {
            if (t instanceof GeneralSecurityException || t instanceof JOSEException
                    || t instanceof VcDataIntegrityCryptographicSuiteException || t instanceof VerificationMethodException
                    || t instanceof DidLogMetaPeekerException || t instanceof InvalidDidLogException
                    || t instanceof ProofOfPossessionVerifierException || t instanceof ProofOfPossessionCreatorException
                    || t instanceof DidLogCreatorStrategyException || t instanceof DidLogUpdaterStrategyException
                    || t instanceof DidLogDeactivatorStrategyException || t instanceof UpdateKeysDidMethodParameterException
                    || t instanceof NextKeyHashesDidMethodParameterException) {
                return CRYPTO_VERIFICATION;
            }
        }
        if (throwable instanceof ParameterException
                || (throwable instanceof JCommanderRunner.CommandException && throwable.getCause() == null)) {
            return USAGE;
        }
        return UNEXPECTED;
    }
}
