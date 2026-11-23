package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * {@link KeyMaterialLoader} reading the key pair from a Java KeyStore (PKCS12) file.
 * <p>
 * Signing proof of possession JWTs is not supported by this key source.
 */
final class JksKeyMaterialLoader implements KeyMaterialLoader {

    private final Path jksFile;
    private final String password;
    private final String alias;

    JksKeyMaterialLoader(Path jksFile, String password, String alias) {
        this.jksFile = jksFile;
        this.password = password;
        this.alias = alias;
    }

    @Override
    public VcDataIntegrityCryptographicSuite loadCryptographicSuite() throws VcDataIntegrityCryptographicSuiteException {
        // CAUTION Different store and key passwords not supported for PKCS12 KeyStores
        try (var jksInputStream = Files.newInputStream(jksFile)) {
            return new EdDsaJcs2022VcDataIntegrityCryptographicSuite(jksInputStream, password, alias, password); // supplied external key pair
        } catch (IOException e) {
            throw new VcDataIntegrityCryptographicSuiteException("Unable to load KeyStore:" + e.getMessage(), e);
        }
    }
}
