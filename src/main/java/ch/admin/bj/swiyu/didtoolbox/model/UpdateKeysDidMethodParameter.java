package ch.admin.bj.swiyu.didtoolbox.model;

import ch.admin.bj.swiyu.didtoolbox.Ed25519Utils;
import ch.admin.bj.swiyu.didtoolbox.PemUtils;
import ch.admin.eid.did_sidekicks.DidSidekicksException;

import java.io.File;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * The interface describes the <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
 * DID method parameter:
 * <pre>
 * A JSON array of multikey formatted public keys associated with the private keys that are authorized to sign the log entries that update the DID.
 * </pre>
 * <p>
 * The interface also features a several convenient static factory methods focusing on standard Java types typically used for the purpose
 * of holding Ed25519 public keys e.g. {@link PublicKey}, {@link Path} or {@link String}.
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface UpdateKeysDidMethodParameter {

    /**
     * Yet another static factory method of the interface.
     * <p>
     * Assuming a valid Ed25519 public key object can be loaded from the supplied PEM-encoded file on the local filesystem,
     * the helper returns a {@link UpdateKeysDidMethodParameter} object
     *
     * @param pemPath of a PEM-encoded file to load Ed25519 public key from
     * @return a valid {@link UpdateKeysDidMethodParameter} object whose {@link #getUpdateKey()} method
     * delivers hash of the public key stored in the supplied {@link Path} object
     * @throws UpdateKeysDidMethodParameterException see {@link PemUtils#readEd25519PublicKeyPemFileToMultibase(Path)}
     */
    static UpdateKeysDidMethodParameter of(Path pemPath) throws UpdateKeysDidMethodParameterException {
        String paramValue;
        try {
            paramValue = PemUtils.readEd25519PublicKeyPemFileToMultibase(pemPath);
        } catch (DidSidekicksException e) {
            throw new UpdateKeysDidMethodParameterException(e);
        }

        return new UpdateKeysDidMethodParameter() {
            @Override
            public String getUpdateKey() {
                return paramValue;
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getUpdateKey());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param key Ed25519 (either private or public) key to encode. It is assumed the key supports its primary encoding format.
     *            Otherwise, {@link IllegalArgumentException} is thrown
     * @return a valid {@link UpdateKeysDidMethodParameter} object whose {@link #getUpdateKey()} method
     * delivers hash of the public key stored in the supplied {@link PublicKey} object
     */
    static UpdateKeysDidMethodParameter of(PublicKey key) {

        return new UpdateKeysDidMethodParameter() {
            @Override
            public String getUpdateKey() {
                return Ed25519Utils.toMultibase(key);
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getUpdateKey());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param multibaseKey multibase-encoded Ed25519 public key
     * @return a valid {@link UpdateKeysDidMethodParameter} object whose {@link #getUpdateKey()} method
     * delivers hash of the public key stored in the supplied {@link String} object
     */
    static UpdateKeysDidMethodParameter of(String multibaseKey) {

        return new UpdateKeysDidMethodParameter() {
            @Override
            public String getUpdateKey() {
                return multibaseKey;
            }

            @Override
            public boolean equals(Object obj) {
                return this.defaultEquals(obj);
            }

            @Override
            public int hashCode() {
                return Objects.hash(this.getUpdateKey());
            }
        };
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param pemFiles featuring Ed25519 public keys in PEM format
     * @return a set of {@link UpdateKeysDidMethodParameter} objects, for each member of the supplied {@link File} set, never {@code null}
     * @throws UpdateKeysDidMethodParameterException
     */
    static Set<UpdateKeysDidMethodParameter> of(Set<File> pemFiles) throws UpdateKeysDidMethodParameterException {

        var set = new HashSet<UpdateKeysDidMethodParameter>();
        if (pemFiles == null || pemFiles.isEmpty()) {
            return set;
        }

        for (var pemFile : pemFiles) {
            set.add(of(pemFile.toPath())); // may throw UpdateKeysDidMethodParameterException
        }

        return set;
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param pemPaths featuring Ed25519 public keys in PEM format
     * @return a set of {@link UpdateKeysDidMethodParameter} objects, for each member of the supplied {@link Path} object, never {@code null}
     * @throws UpdateKeysDidMethodParameterException
     */
    static Set<UpdateKeysDidMethodParameter> of(Path... pemPaths) throws UpdateKeysDidMethodParameterException {

        var set = new HashSet<UpdateKeysDidMethodParameter>();
        if (pemPaths == null) {
            return set;
        }

        for (var pemPath : pemPaths) {
            set.add(of(pemPath)); // may throw UpdateKeysDidMethodParameterException
        }

        return set;
    }

    /**
     * Yet another static factory method of the interface.
     *
     * @param publicKeys featuring Ed25519 public keys
     * @return a set of {@link UpdateKeysDidMethodParameter} objects, for each member of the supplied {@link PublicKey} object, never {@code null}
     */
    static Set<UpdateKeysDidMethodParameter> of(PublicKey... publicKeys) {

        var set = new HashSet<UpdateKeysDidMethodParameter>();
        if (publicKeys == null) {
            return set;
        }

        for (var publicKey : publicKeys) {
            set.add(of(publicKey));
        }

        return set;
    }

    /**
     * Delivers a <a href="https://identity.foundation/didwebvh/v1.0/#term:multikey">multikey</a> formatted public key
     * associated with the private key that is authorized to sign the
     * <a href="https://identity.foundation/didwebvh/v1.0/#term:log-entries">DID log entry</a> when updating the DID log.
     *
     * @return hash of for a public key suitable for the
     * <a href="https://identity.foundation/didwebvh/v1.0/#didwebvh-did-method-parameters">updateKeys</a>
     * DID method parameter
     */
    String getUpdateKey();

    /**
     * Effectively, this is the default {@link Object#equals(Object)} implementation introduced for the sake of preventing:
     * <pre>Default method 'equals' overrides a member of 'java.lang.Object'</pre>
     *
     * @param obj the reference object with which to compare.
     * @return {@code true} if this object is the same as the obj
     * argument; {@code false} otherwise.
     */
    default boolean defaultEquals(Object obj) {

        return (obj instanceof UpdateKeysDidMethodParameter other) &&
                this.getUpdateKey().equals(other.getUpdateKey());
    }
}
