package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;

import java.time.ZonedDateTime;

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
     * Add a data integrity proof to a supplied <b>unsecured data document</b> ("a map that contains no proof values"), thus producing
     * a <b>secured data document</b> ("a map that contains one or more proof values").
     *
     * @param unsecuredDocument to make "secure" in terms of adding a data integrity proof to it,
     *                          as <a href="https://www.w3.org/TR/vc-data-integrity/#dfn-unsecured-data-document">specified</a>
     *                          ("unsecured data document is a map (JSON object) that contains no proof values")
     * @param challenge         self-explanatory
     * @param proofPurpose      the reason the proof was created,
     *                          as specified by <a href="https://www.w3.org/TR/vc-data-integrity/#proofs">Verifiable Credential Data Integrity 1.0</a>,
     *                          typically "assertionMethod" or "authentication"
     * @param dateTime          of the proof creation (in <a href="https://www.rfc-editor.org/rfc/rfc3339.html">RFC3339</a> format)
     * @return String representing a "secured" document i.e. the supplied {@code unsecuredDocument} featuring a data integrity proof
     * @throws VcDataIntegrityCryptographicSuiteException if operation fails for any reason
     */
    String addProof(String unsecuredDocument,
                    String challenge,
                    String proofPurpose,
                    ZonedDateTime dateTime) throws VcDataIntegrityCryptographicSuiteException;
}
