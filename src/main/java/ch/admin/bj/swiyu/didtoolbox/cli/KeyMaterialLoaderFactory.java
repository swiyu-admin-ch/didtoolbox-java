package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.AbstractDidLogCommandBase;
import ch.admin.bj.swiyu.didtoolbox.cli.jcommander.CreateProofOfPossessionCommand;
import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreLoader;

import java.io.File;
import java.util.Optional;

/**
 * Selects the {@link KeyMaterialLoader} matching the key source supplied via CLI parameters.
 * <p>
 * The mutual exclusivity of the key sources is already enforced by
 * {@link ch.admin.bj.swiyu.didtoolbox.cli.jcommander.validator.CommandParametersValidator} at parse time,
 * so the first complete key source found wins.
 */
final class KeyMaterialLoaderFactory {

    private KeyMaterialLoaderFactory() {
    }

    /**
     * @param command containing the key source parameters
     * @return the matching loader, or {@link Optional#empty()} if no (complete) key source is supplied
     */
    static Optional<KeyMaterialLoader> from(AbstractDidLogCommandBase command) {
        return pem(command.signingKeyPemFile)
                .or(() -> jks(command.jksFile, command.jksPassword, command.jksAlias))
                .or(() -> primus(command.securosysPrimusKeyStoreLoader, command.primusKeyAlias, command.primusKeyPassword));
    }

    /**
     * @param command containing the key source parameters (a Java KeyStore is not supported here)
     * @return the matching loader, or {@link Optional#empty()} if no (complete) key source is supplied
     */
    static Optional<KeyMaterialLoader> from(CreateProofOfPossessionCommand command) {
        return pem(command.signingKeyPemFile)
                .or(() -> primus(command.securosysPrimusKeyStoreLoader, command.primusKeyAlias, command.primusKeyPassword));
    }

    private static Optional<KeyMaterialLoader> pem(File signingKeyPemFile) {
        return Optional.ofNullable(signingKeyPemFile)
                .map(file -> new PemKeyMaterialLoader(file.toPath()));
    }

    private static Optional<KeyMaterialLoader> jks(File jksFile, String password, String alias) {
        if (jksFile == null || alias == null) {
            return Optional.empty();
        }
        return Optional.of(new JksKeyMaterialLoader(jksFile.toPath(), password, alias));
    }

    private static Optional<KeyMaterialLoader> primus(PrimusKeyStoreLoader primusKeyStoreLoader, String alias, String password) {
        if (primusKeyStoreLoader == null || alias == null) {
            return Optional.empty();
        }
        return Optional.of(new PrimusKeyMaterialLoader(primusKeyStoreLoader, alias, password));
    }
}
