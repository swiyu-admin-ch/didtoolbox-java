package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.Ed25519Utils;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import io.ipfs.multibase.Base58;

import java.io.File;
import java.security.Key;

/**
 * The interface describes calculation the hash string as {@code base58btc(multihash(multikey))}, where:
 * <ol>
 *      <li>{@code multikey} is the multikey representation of a public key</li>
 *      <li>{@code multihash} is an implementation of the <a href="https://www.w3.org/TR/controller-document/#multihash">multihash</a> specification.
 *      Its output is a hash of the input using the associated {@code <hash algorithm>},
 *      prefixed with a hash algorithm identifier and the hash size.</li>
 *      <li>{@code <hash algorithm>} is the hash algorithm used by the DID Controller.
 *      The hash algorithm MUST be one listed in the parameters defined by the version of a {@code did:*} (e.g. {@code did:webvh})
 *      specification being used by the DID Controller.</li>
 *      <li>{@code base58btc} is an implementation of the base58btc function (converts data to a {@code base58} encoding).
 *      Its output is the base58 encoded string of its input.</li>
 * </ol>
 * As such, the helper can be used out-of-the-box for the purpose of <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">pre-rotation-key-hash-generation-and-verification</a>.
 */
public interface NextKeyHashSource {

    /**
     *
     * @return hash string for the supplied multikey
     */
    String getHash();

    /**
     * Assuming a valid Ed25519 public key object can be loaded from the supplied PEM-encoded file on the local filesystem,
     * the helper returns a {@link NextKeyHashSource} object
     *
     * @param pemFile to load an Ed25519 public key from
     * @return
     * @throws NextKeyHashSourceException see {@link PemUtils#readEd25519PublicKeyPemFileToMultibase(File)}
     */
    static NextKeyHashSource of(File pemFile) throws NextKeyHashSourceException {
        String hash;
        try {
            hash = Base58.encode(JCSHasher.multihash(
                    PemUtils.readEd25519PublicKeyPemFileToMultibase(pemFile)));
        } catch (DidSidekicksException e) {
            throw new NextKeyHashSourceException(e);
        }

        return () -> hash;
    }

    /**
     *
     * @param key Ed25519 (either private or public) key to encode. It is assumed the key supports its primary encoding format.
     *            Otherwise, {@link IllegalArgumentException} is thrown
     * @throws NextKeyHashSourceException
     */
    static NextKeyHashSource of(Key key) throws NextKeyHashSourceException {
        return () -> Base58.encode(JCSHasher.multihash(Ed25519Utils.toMultibase(key)));
    }

    static NextKeyHashSource of(String multibaseKey) {
        return () -> Base58.encode(JCSHasher.multihash(multibaseKey));
    }
}
