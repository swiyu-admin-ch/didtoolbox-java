package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import ch.admin.bj.swiyu.didtoolbox.VerificationMethodKeyProvider;

import java.time.ZonedDateTime;

/**
 * The interface describes a cryptographic suite in charge of creating and verifying data integrity proofs, as specified by
 * <a href="https://www.w3.org/TR/vc-data-integrity/#cryptographic-suites">Verifiable Credential Data Integrity 1.0</a>.
 *
 * @since 1.8.0
 */
@SuppressWarnings("PMD.ImplicitFunctionalInterface")
public interface VcDataIntegrityCryptographicSuite extends VerificationMethodKeyProvider {

    /**
     * Add a data integrity proof to a supplied <b>unsecured data document</b> ("a map that contains no proof values"), thus producing
     * a <b>secured data document</b> ("a map that contains one or more proof values").
     *
     * @param unsecuredDocument to make "secure" in terms of adding a data integrity proof to it
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
