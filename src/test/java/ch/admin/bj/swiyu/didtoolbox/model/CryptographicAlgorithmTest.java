package ch.admin.bj.swiyu.didtoolbox.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptographicAlgorithmTest {

    @Test
    void toString_returnsAlgorithmName() {
        assertEquals("P-256", CryptographicAlgorithm.P256.toString());
        assertEquals("Ed25519", CryptographicAlgorithm.ED25519.toString());
    }
}
