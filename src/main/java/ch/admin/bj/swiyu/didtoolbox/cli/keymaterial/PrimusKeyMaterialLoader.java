package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cryptography.ProofOfPossessionJWSSigner;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusEd25519VerificationMethodKeyProviderImpl;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import com.nimbusds.jose.JOSEException;

import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.util.Arrays;

/**
 * {@link KeyMaterialLoader} recovering the key pair from a Securosys Primus (HSM) Keystore.
 */
final class PrimusKeyMaterialLoader implements KeyMaterialLoader {

    private final PrimusKeyStoreLoader primusKeyStoreLoader;
    private final String alias;
    // Optional, may be null. Deliberately a String: JCommander only ever delivers the password as a String,
    // so a char[] field would not limit its lifetime.
    private final String password;

    /**
     * @param primusKeyStoreLoader to recover the key pair from
     * @param alias                of the key pair
     * @param password             for recovering the key pair, optional i.e. may be {@code null}
     */
    PrimusKeyMaterialLoader(PrimusKeyStoreLoader primusKeyStoreLoader, String alias, String password) {
        this.primusKeyStoreLoader = primusKeyStoreLoader;
        this.alias = alias;
        this.password = password;
    }

    @Override
    public VcDataIntegrityCryptographicSuite loadCryptographicSuite() throws VcDataIntegrityCryptographicSuiteException {
        var passwordChars = password == null ? null : password.toCharArray(); // the password is optional, null is explicitly supported by PrimusKeyStoreLoader#loadKeyPair
        try {
            return new PrimusEd25519VerificationMethodKeyProviderImpl(primusKeyStoreLoader, alias, passwordChars); // supplied external key pair
        } catch (UnrecoverableEntryException | KeyStoreException | NoSuchAlgorithmException | KeyException e) {
            throw new VcDataIntegrityCryptographicSuiteException("Failed to initialize primus:" + e.getMessage(), e);
        } finally {
            wipe(passwordChars);
        }
    }

    @Override
    public ProofOfPossessionJWSSigner loadProofOfPossessionSigner(String kid) throws GeneralSecurityException, JOSEException {
        var passwordChars = password == null ? null : password.toCharArray(); // the password is optional, null is explicitly supported by PrimusKeyStoreLoader#loadKeyPair
        try {
            return ProofOfPossessionJWSSigner.of(primusKeyStoreLoader, alias, passwordChars, kid);
        } finally {
            wipe(passwordChars);
        }
    }

    @SuppressWarnings("PMD.UseVarargs") // a single password buffer, not an argument list
    private static void wipe(char[] passwordChars) {
        if (passwordChars != null) {
            Arrays.fill(passwordChars, ' ');
        }
    }
}
