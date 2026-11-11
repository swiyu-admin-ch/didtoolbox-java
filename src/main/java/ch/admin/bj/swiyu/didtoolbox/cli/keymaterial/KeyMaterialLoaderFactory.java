package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;

import java.io.File;
import java.util.Optional;

/**
 * Creates the {@link KeyMaterialLoader} for each of the supported key sources.
 * <p>
 * Every method yields {@link Optional#empty()} if its key source is not (completely) supplied,
 * so that a command is able to chain the ones matching the key sources it supports.
 */
public final class KeyMaterialLoaderFactory {

    private KeyMaterialLoaderFactory() {
    }

    /**
     * @param signingKeyPemFile the private key file in PEM format, may be {@code null}
     * @return the matching loader, or {@link Optional#empty()} if the key source is not supplied
     */
    public static Optional<KeyMaterialLoader> pem(File signingKeyPemFile) {
        return Optional.ofNullable(signingKeyPemFile)
                .map(file -> new PemKeyMaterialLoader(file.toPath()));
    }

    /**
     * @param file     the Java KeyStore (PKCS12) file, may be {@code null}
     * @param password of the Java KeyStore
     * @param alias    of the entry to process, may be {@code null}
     * @return the matching loader, or {@link Optional#empty()} if the key source is not (completely) supplied
     */
    public static Optional<KeyMaterialLoader> jks(File file, String password, String alias) {
        if (file == null || alias == null) {
            return Optional.empty();
        }
        return Optional.of(new JksKeyMaterialLoader(file.toPath(), password, alias));
    }

    /**
     * @param primusKeyStoreLoader to recover the key pair from, may be {@code null}
     * @param alias                of the key pair, may be {@code null}
     * @param password             for recovering the key pair, optional i.e. may be {@code null}
     * @return the matching loader, or {@link Optional#empty()} if the key source is not (completely) supplied
     */
    public static Optional<KeyMaterialLoader> primus(PrimusKeyStoreLoader primusKeyStoreLoader, String alias, String password) {
        if (primusKeyStoreLoader == null || alias == null) {
            return Optional.empty();
        }
        return Optional.of(new PrimusKeyMaterialLoader(primusKeyStoreLoader, alias, password));
    }
}
