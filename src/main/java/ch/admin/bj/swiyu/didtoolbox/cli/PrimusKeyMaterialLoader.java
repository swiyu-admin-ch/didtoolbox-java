package ch.admin.bj.swiyu.didtoolbox.cli;

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
    private final String password;

    PrimusKeyMaterialLoader(PrimusKeyStoreLoader primusKeyStoreLoader, String alias, String password) {
        this.primusKeyStoreLoader = primusKeyStoreLoader;
        this.alias = alias;
        this.password = password;
    }

    @Override
    public VcDataIntegrityCryptographicSuite loadCryptographicSuite() throws VcDataIntegrityCryptographicSuiteException {
        var passwordChars = password.toCharArray();
        try {
            return new PrimusEd25519VerificationMethodKeyProviderImpl(primusKeyStoreLoader, alias, passwordChars); // supplied external key pair
        } catch (UnrecoverableEntryException | KeyStoreException | NoSuchAlgorithmException | KeyException e) {
            throw new VcDataIntegrityCryptographicSuiteException("Failed to initialize primus:" + e.getMessage(), e);
        } finally {
            Arrays.fill(passwordChars, ' ');
        }
    }

    @Override
    public ProofOfPossessionJWSSigner loadProofOfPossessionSigner(String kid) throws GeneralSecurityException, JOSEException {
        var passwordChars = password.toCharArray();
        try {
            return ProofOfPossessionJWSSigner.of(primusKeyStoreLoader, alias, passwordChars, kid);
        } finally {
            Arrays.fill(passwordChars, ' ');
        }
    }
}
