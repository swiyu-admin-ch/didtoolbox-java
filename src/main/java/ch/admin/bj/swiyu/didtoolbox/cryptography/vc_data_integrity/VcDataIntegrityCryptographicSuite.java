package ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity;

import ch.admin.bj.swiyu.didtoolbox.cryptography.Base58;
import ch.admin.bj.swiyu.didtoolbox.did.VerificationMethodKeyProvider;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.JcsSha256Hasher;
import com.google.gson.JsonObject;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

/**
 * The interface describes a cryptographic suite in charge of creating and (optionally) verifying data integrity proofs, as specified by
 * <a href="https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites">Verifiable Credential Data Integrity 1.0</a>.
 * <p>
 * <b>CAUTION</b> A {@link VcDataIntegrityCryptographicSuite} implementation is not required to implement the
 * {@link VcDataIntegrityCryptographicSuite#verifyProof(String, String)} method
 * (in which case, an unchecked exception is thrown by default, if the method is called),
 * thus remaining exclusively capable of data integrity proof creation.
 *
 * @since 1.8.0
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface VcDataIntegrityCryptographicSuite extends VerificationMethodKeyProvider {
    String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    String EDDSA_JCS_2022 = "eddsa-jcs-2022";
    String DID_KEY = "did:key:";
    String PROOF_PURPOSE_AUTHENTICATION = "authentication";
    String PROOF_PURPOSE_ASSERTION_METHOD = "assertionMethod";

    /**
     * Verify a <b>data integrity proof</b> ("a set of attributes that represent a digital proof and the parameters required to verify it. A digital signature is a type of data integrity proof.")
     * given a "<b>secured data document</b> ("a map (JSON object) that contains one or more proof values"),
     * as <a href="https://www.w3.org/TR/vc-data-integrity/#verify-proof">specified</a>.
     * Either a <b>cryptosuite verification result</b> is produced, or an error.
     * <p>
     * <b>CAUTION</b> A {@link VcDataIntegrityCryptographicSuite} implementation is not required to implement this
     * method (in which case, an unchecked exception is thrown by default, if the method is called),
     * thus remaining exclusively capable of data integrity proof creation.
     *
     * @param securedDocument           map (JSON object) that contains one or more proof values,
     *                                  as <a href="https://www.w3.org/TR/vc-data-integrity/#dfn-secured-data-document">specified</a>
     * @param dataIntegrityProofOptions set of attributes (JSON object) that represent a digital proof and the parameters required to verify it.
     *                                  A digital signature is a type of data integrity proof
     * @return boolean flag denoting verification outcome
     * @throws VcDataIntegrityCryptographicSuiteException if operation fails for any reason
     * @throws IllegalArgumentException                   if not implemented (default)
     */
    default boolean verifyProof(String securedDocument,
                                String dataIntegrityProofOptions) throws VcDataIntegrityCryptographicSuiteException {
        throw new IllegalArgumentException("not implemented yet");
    }

    /**
     * As specified by <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">Data Integrity EdDSA Cryptosuites v1.0</a>.
     * <p>See <a href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022">example</a>
     *
     * <p>A proof contains the attributes specified in the <a href="https://www.w3.org/TR/vc-data-integrity/#proofs">Proofs</a> section
     * of <a href="https://www.w3.org/TR/vc-di-eddsa/#bib-vc-data-integrity">VC-DATA-INTEGRITY</a> with the following restrictions.
     *
     * <p>The type property MUST be DataIntegrityProof.
     *
     * <p>The cryptosuite property of the proof MUST be "eddsa-rdfc-2022" or "eddsa-jcs-2022".
     * CAUTION This implementation supports currently only "eddsa-jcs-2022" as specified by https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022.
     *
     * <p>The proofValue property of the proof MUST be a detached EdDSA signature produced according to
     * <a href="https://www.w3.org/TR/vc-di-eddsa/#bib-rfc8032">RFC8032</a>,
     * encoded using the base-58-btc header and alphabet as described in the
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">Multibase</a> section of
     * <a href="https://www.w3.org/TR/controller-document/">Controlled Identifier Document</a>.
     *
     * @param unsecuredDocument             to create a proof for
     * @param challenge                     self-explanatory
     * @param proofPurpose                  typically "assertionMethod" or "authentication"
     * @param dateTime                      of the proof creation
     * @return JsonObject representing the data integrity proof
     * @throws DidSidekicksException may come from a hasher
     */
    default JsonObject buildDataIntegrityProof(JsonObject unsecuredDocument,
                                                     String challenge,
                                                     String proofPurpose,
                                                     ZonedDateTime dateTime) throws VcDataIntegrityCryptographicSuiteException {
        /*
        https://identity.foundation/didwebvh/v0.3/#data-integrity-proof-generation-and-first-log-entry:
        The last step in the creation of the first log entry is the generation of the data integrity proof.
        One of the keys in the updateKeys parameter MUST be used (in the form of a did:key) to generate the signature in the proof,
        with the versionId value (item 1 of the did log) used as the challenge item.
        The generated proof is added to the JSON as the fifth item, and the entire array becomes the first entry in the DID Log.
         */
        var proof = new JsonObject();

        // According to https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022:
        // 2) If unsecuredDocument.@context is present, set proof.@context to unsecuredDocument.@context.
        var ctx = unsecuredDocument.get("@context");
        if (ctx != null) {
            proof.add("@context", ctx);
        }

        proof.addProperty("type", DATA_INTEGRITY_PROOF);
        // According to https://www.w3.org/TR/vc-di-eddsa/#proof-configuration-eddsa-jcs-2022
        proof.addProperty("cryptosuite", EDDSA_JCS_2022);
        proof.addProperty("created", DateTimeFormatter.ISO_INSTANT.format(dateTime.truncatedTo(ChronoUnit.SECONDS)));

        /*
        The data integrity proof verificationMethod is the did:key from the first log entry, and the challenge is the versionId from this log entry.
         */
        proof.addProperty("verificationMethod", DID_KEY + this.getVerificationKeyMultibase() + '#' + this.getVerificationKeyMultibase());
        proof.addProperty("proofPurpose", proofPurpose);
        if (challenge != null) {
            proof.addProperty("challenge", challenge);
        }

        // See https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022
        //     https://www.w3.org/TR/controller-document/#multibase-0
        JcsSha256Hasher hasher = JcsSha256Hasher.Companion.build();
        try {
            proof.addProperty("proofValue", 'z' + Base58.encode(
                    this.generateSignature(
                            HexFormat.of().parseHex(
                                    hasher.encodeHex(proof.toString()) + hasher.encodeHex(unsecuredDocument.toString())))));
        } catch (DidSidekicksException e) {
            throw new VcDataIntegrityCryptographicSuiteException(e);
        }

        return proof;
    }
}
