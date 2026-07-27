package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

public class VcDataIntegrityCryptographicSuiteTest {

    @Test
    void verifyProof_defaultImplementation_throwsIllegalArgumentException() {
        var cryptoSuite = new CryptographicSuite();
        assertThrowsExactly(IllegalArgumentException.class, () -> cryptoSuite.verifyProof("", ""));
    }

    // Class that just implements the VcDataIntegrityCryptographicSuite interface to test the default implementations.
    private class CryptographicSuite implements VcDataIntegrityCryptographicSuite {
        @Override
        public String addProof(String unsecuredDocument, String challenge, String proofPurpose, ZonedDateTime dateTime) throws VcDataIntegrityCryptographicSuiteException {
            return "";
        }

        @Override
        public String getVerificationKeyMultibase() {
            return "";
        }

        @Override
        public byte[] generateSignature(byte[] message) {
            return new byte[0];
        }

        @Override
        public boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys) {
            return false;
        }
    }
}
