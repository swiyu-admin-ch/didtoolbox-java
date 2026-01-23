package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.Ed25519Utils;
import ch.admin.bj.swiyu.didtoolbox.JCSHasher;
import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import io.ipfs.multibase.Base58;

import java.io.File;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The interface describes the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">nextKeyHashes</a>
 * DID method parameter, which is calculated as hash of <a href="https://identity.foundation/didwebvh/v1.0/#term:multikey">multikey</a>
 * formatted public key, as specified by <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">Pre-Rotation Key Hash Generation and Verification</a>.
 * <p>
 * The calculation of such hash string can be expressed as {@code base58btc(multihash(multikey))}, where:
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
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding Ed25519 public keys e.g. {@link PublicKey}, {@link Path} or {@link String}.
 * Given so, these helpers can be used out-of-the-box for the purpose of <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">pre-rotation-key-hash-generation-and-verification</a>.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface NextKeyHashesDidMethodParameter {

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming a valid Ed25519 public key object can be loaded from the supplied PEM-encoded file on the local filesystem,
     * the helper returns a {@link NextKeyHashesDidMethodParameter} object
     *
     * @param pemPath to a PEM-encoded file to load Ed25519 public key from
     * @return a valid {@link NextKeyHashesDidMethodParameter} object whose {@link #getNextKeyHash()} method
     * delivers hash of the public key stored in the supplied {@link File} object
     * @throws NextKeyHashesDidMethodParameterException see {@link PemUtils#readEd25519PublicKeyPemFileToMultibase(Path)}
     */
    static NextKeyHashesDidMethodParameter of(Path pemPath) throws NextKeyHashesDidMethodParameterException {
        String hash;
        try {
            hash = Base58.encode(JCSHasher.multihash(PemUtils.readEd25519PublicKeyPemFileToMultibase(pemPath)));
        } catch (DidSidekicksException e) {
            throw new NextKeyHashesDidMethodParameterException(e);
        }

        return new NextKeyHashesDidMethodParameter() {
            @Override
            public String getNextKeyHash() {
                return hash;
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getNextKeyHash());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param publicKey Ed25519 public key to encode. It is assumed the key supports its primary encoding format.
     *                  Otherwise, {@link IllegalArgumentException} is thrown
     * @return a valid {@link NextKeyHashesDidMethodParameter} object whose {@link #getNextKeyHash()} method
     * delivers hash of the Ed25519 public key stored in the supplied {@link PublicKey} object
     * @throws NextKeyHashesDidMethodParameterException
     */
    static NextKeyHashesDidMethodParameter of(PublicKey publicKey) throws NextKeyHashesDidMethodParameterException {

        return new NextKeyHashesDidMethodParameter() {
            @Override
            public String getNextKeyHash() {
                return Base58.encode(JCSHasher.multihash(Ed25519Utils.toMultibase(publicKey)));
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getNextKeyHash());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param multibaseKey multibase-encoded Ed25519 public key
     * @return a valid {@link NextKeyHashesDidMethodParameter} object whose {@link #getNextKeyHash()} method
     * delivers hash of the Ed25519 public key stored in the supplied {@link String} object
     */
    static NextKeyHashesDidMethodParameter of(String multibaseKey) {
        return new NextKeyHashesDidMethodParameter() {
            @Override
            public String getNextKeyHash() {
                return Base58.encode(JCSHasher.multihash(multibaseKey));
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getNextKeyHash());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param pemFiles
     * @return a set of {@link NextKeyHashesDidMethodParameter} objects, for each member of the supplied {@link File} set, never {@code null}
     * @throws NextKeyHashesDidMethodParameterException
     */
    static Set<NextKeyHashesDidMethodParameter> of(Set<File> pemFiles) throws NextKeyHashesDidMethodParameterException {

        var set = new HashSet<NextKeyHashesDidMethodParameter>();
        if (pemFiles == null || pemFiles.isEmpty()) {
            return set;
        }

        for (var pemFile : pemFiles) {
            set.add(of(pemFile.toPath())); // may throw NextKeyHashesDidMethodParameterException
        }

        return set;
    }

    /**
     *
     * @param pemFiles
     * @return a valid {@link JsonArray} object featuring distinct {@code nextKeyHash} values, never {@code null}
     * @throws NextKeyHashesDidMethodParameterException
     */
    static JsonArray getHashesAsJsonArray(Set<File> pemFiles) throws NextKeyHashesDidMethodParameterException {
        var nextKeyHashesJsonArray = new JsonArray();

        if (pemFiles == null || pemFiles.isEmpty()) {
            return nextKeyHashesJsonArray;
        }

        for (var pemFile : pemFiles) {

            var nextKeyHash = of(pemFile.toPath()).getNextKeyHash(); // may throw NextKeyHashesDidMethodParameterException

            if (!nextKeyHashesJsonArray.contains(new JsonPrimitive(nextKeyHash))) {
                nextKeyHashesJsonArray.add(nextKeyHash);
            }
        }

        return nextKeyHashesJsonArray;
    }

    /**
     *
     * @param params
     * @return a valid JsonArray featuring distinct {@code nextKeyHash} values
     * @throws NextKeyHashesDidMethodParameterException
     */
    static JsonArray collectHashesIntoJsonArray(Set<NextKeyHashesDidMethodParameter> params) throws NextKeyHashesDidMethodParameterException {
        var nextKeyHashesJsonArray = new JsonArray();

        if (params == null || params.isEmpty()) {
            return nextKeyHashesJsonArray;
        }

        params.forEach(param -> {

            var nextKeyHash = param.getNextKeyHash();

            if (!nextKeyHashesJsonArray.contains(new JsonPrimitive(nextKeyHash))) {
                nextKeyHashesJsonArray.add(nextKeyHash);
            }
        });

        return nextKeyHashesJsonArray;
    }

    /**
     * Delivers hash of a <a href="https://identity.foundation/didwebvh/v1.0/#term:multikey">multikey</a> formatted public key
     * (w.r.t. <a href="https://identity.foundation/didwebvh/v1.0/#pre-rotation-key-hash-generation-and-verification">Pre-Rotation Key Hash Generation and Verification</a>)
     * that MAY be added to the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">nextKeyHashes</a>
     * list in the next <a href="https://identity.foundation/didwebvh/v1.0/#term:log-entry">DID log entry</a>.
     *
     * @return hash of a public key suitable for the
     * <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">nextKeyHashes</a>
     * DID method parameter
     */
    String getNextKeyHash();

    /**
     * Effectively, this is the default {@link Object#equals(Object)} implementation introduced for the sake of preventing:
     * <pre>Default method 'equals' overrides a member of 'java.lang.Object'</pre>
     *
     * @param obj the reference object with which to compare.
     * @return {@code true} if this object is the same as the obj
     * argument; {@code false} otherwise.
     */
    default boolean defaultEquals(Object obj) {

        if (!(obj instanceof NextKeyHashesDidMethodParameter other)) return false;

        return this.getNextKeyHash().equals(other.getNextKeyHash());
    }
}
