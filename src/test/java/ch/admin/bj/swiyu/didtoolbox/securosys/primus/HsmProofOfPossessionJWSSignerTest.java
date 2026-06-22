package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionCreator;
import ch.admin.bj.swiyu.didtoolbox.ProofOfPossessionVerifier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Class to test different HSM proof of possession jws signer implementations.
 */
class HsmProofOfPossessionJWSSignerTest {

    /**
     * Tests the pkcs11 provider for general HsmProofOfPossessionJWSSigner.
     * Requires specific system precondition configured in the provided dockerfile found in src/test/data/pkcs11.
     * Simply run
     * {@code
     *  docker run -it -v .:/app -v $HOME/.m2:/home/mvn/.m2 $(docker build -q ./src/test/data/pkcs11/) mvn test
     * }
     * @throws Exception in case of failure
     */
    @Test
    @EnabledIfEnvironmentVariable(named = "PKCS11_TEST", matches = "true")
    void newPkcs11Signer_createAndVerifyPOP_success() throws Exception {
        var cfgPath = "/config/pkcs11.config";
        var keyId = "1111";
        var secret = "secret";
        var kid = "did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org#assert01";
        var signer = HsmProofOfPossessionJWSSigner.newPkcs11Signer(cfgPath, secret, keyId, kid);
        var popCreator = new ProofOfPossessionCreator(signer);

        var nonce = "myNonce";
        var pop = popCreator.create(nonce, Duration.ofDays(1));

        var didLog = """
                {"versionId":"1-QmaxVNS1PyTZRMoGyZ1tyosQyyeWX3QWYwAChhPwj6pwL6","versionTime":"2026-06-22T05:43:16Z","parameters":{"method":"did:webvh:1.0","scid":"QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b","updateKeys":["z6MkfhNVhB62wTEtAbaeokJhK2SDusEWHMypVErrUSq11faC"],"portable":false},"state":{"id":"did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org","profile_version":"swiss-profile-anchor:1.0.0","authentication":["did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org#auth-key-01"],"assertionMethod":["did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org#assert01"],"verificationMethod":[{"id":"did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org#auth-key-01","controller":"did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","x":"o76oVipdHOTFtAD6UEW_Z7ZtB3pa9qoBAPFadg8fXqM","y":"r8w7U0QoS_wvic17O2yaoLS9ExJS5eg04PaBPGSiAfg","kid":"auth-key-01"}},{"id":"did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org#assert01","controller":"did:webvh:QmV1dV8tt3bYnik8R8e5FbL16uQvqH2DsqpUoMJvF8Nc2b:test.org","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert01","x":"S5t3lu2PpAfhkNtLN67JVCrVzVIlZZWOjDSSEAnJW_k","y":"3mrPOhrgpNTPUFNpkgjsYsor3BN7RspGlD7e5ZD41XU"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-06-22T05:43:16Z","verificationMethod":"did:key:z6MkfhNVhB62wTEtAbaeokJhK2SDusEWHMypVErrUSq11faC#z6MkfhNVhB62wTEtAbaeokJhK2SDusEWHMypVErrUSq11faC","proofPurpose":"assertionMethod","proofValue":"z3eayQyHNAvXSWb4jByqpeayMV3r4EQY48EZhnFduE8wnZbBhhSeVHMHVSxfLLBZ726dsnWh7hmwbWkmuGtvnteRx"}]}
                """.trim();

        var popVerifier = new ProofOfPossessionVerifier(didLog);
        assertDoesNotThrow(() -> popVerifier.verify(pop, nonce));
    }
}