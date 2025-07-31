package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.eid.didtoolbox.TrustDidWeb;
import ch.admin.eid.didtoolbox.TrustDidWebException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

public class ProofOfPossessionUtilTest {

    @Test
    void testProofOfPossession() throws IOException, InvalidKeySpecException, TrustDidWebException, ParseException, JOSEException, DidLogMetaPeekerException {
        var publicKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "public.pem");
        var privateKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "private.pem");
        var privateKey = PemUtils.getPrivateKeyEd25519(PemUtils.readPemObject(new FileReader(privateKeyFile)));
        var nonce = "HelloWorld";

        var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
        var didLog = TestUtil.buildInitialDidLogEntry(signer);

        var didTdw = DidLogMetaPeeker.peek(didLog).didDocId;
        var didWeb = TrustDidWeb.Companion.read(didTdw, didLog);

        // create proof
        var proof = ProofOfPossessionUtil.createProofOfPossession(privateKey, didWeb, nonce);

        // verify proof
        var isValid = ProofOfPossessionUtil.isValid(proof, nonce, didWeb);
        assert(isValid);
        assert(proof.getHeader().getAlgorithm().equals(JWSAlgorithm.Ed25519));
        assert(didLog.contains(proof.getHeader().getKeyID()));
        assert(proof.getPayload().toJSONObject().get("nonce").toString().equals(nonce));
    }

    @Test
    void testVerifyProofOfPossessionKeysNotMatching() throws IOException, GeneralSecurityException, DidLogMetaPeekerException, TrustDidWebException {
        var publicKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "public.pem");
        var privateKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "private.pem");
        var nonce = "HelloWorld";

        var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
        var didLog = TestUtil.buildInitialDidLogEntry(signer);

        var didTdw = DidLogMetaPeeker.peek(didLog).didDocId;
        var didWeb = TrustDidWeb.Companion.read(didTdw, didLog);

        var kgp =KeyPairGenerator.getInstance("Ed25519");
        var privateKey = kgp.generateKeyPair().getPrivate();

        // create proof
        var jwt = ProofOfPossessionUtil.createProofOfPossession(privateKey, didWeb, nonce);
        var exc = assertThrowsExactly(ProofOfPossessionVerificationException.class, () -> ProofOfPossessionUtil.verify(jwt, nonce, didWeb));
        assertEquals(ProofOfPossessionVerificationException.ErrorCause.InvalidSignature, exc.getErrorCause());
    }

    @Test
    void testVerifyProofOfPossessionExpired() throws ParseException, JOSEException {
        var expiredJWT = SignedJWT.parse( "eyJraWQiOiJkaWQ6a2V5Ono2TWt0ZEFyM2lVUmVVN0hzQ2Y3Sm5vQ2pRNXVycEtUeFpTQzQ5S25qRVZzQTVDQSN6Nk1rdGRBcjNpVVJlVTdIc0NmN0pub0NqUTV1cnBLVHhaU0M0OUtuakVWc0E1Q0EiLCJhbGciOiJFZDI1NTE5In0.eyJleHAiOjE3NTM4NzE5OTAsIm5vbmNlIjoiZm9vIn0.Srooog6HXT8TPReDjkhkvGAwwcqe7MgMDbbOWgqfxo2qs1zrug-DJQPv7_lpTOnJmQpvkO7I_-y9d37QBaC-Cw");
        try {
            ProofOfPossessionUtil.verify(expiredJWT, "foo", null);
            assert(false);
        } catch (ProofOfPossessionVerificationException e) {
            assertEquals(ProofOfPossessionVerificationException.ErrorCause.Expired, e.getErrorCause());
        }
    }

    @Test
    void testVerifyProofOfPossessionNonceNotMatching() throws ParseException, InvalidKeySpecException, JOSEException, DidLogMetaPeekerException, IOException, TrustDidWebException {
        var publicKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "public.pem");
        var privateKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "private.pem");
        var privateKey = PemUtils.getPrivateKeyEd25519(PemUtils.readPemObject(new FileReader(privateKeyFile)));
        var nonce = "bar";

        var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
        var didLog = TestUtil.buildInitialDidLogEntry(signer);

        var didTdw = DidLogMetaPeeker.peek(didLog).didDocId;
        var didWeb = TrustDidWeb.Companion.read(didTdw, didLog);

        // create proof
        var proof = ProofOfPossessionUtil.createProofOfPossession(privateKey, didWeb, nonce);

        try {
            ProofOfPossessionUtil.verify(proof, "foo", null);
            assert(false);
        } catch (ProofOfPossessionVerificationException e) {
            assertEquals(ProofOfPossessionVerificationException.ErrorCause.InvalidNonce, e.getErrorCause());
        }
    }

    @Test
    void testVerifyProofOfPossessionKeyNotFoundInDID() throws ParseException, GeneralSecurityException, JOSEException, DidLogMetaPeekerException, IOException, TrustDidWebException {
        var nonce = "bar";
        var publicKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "public.pem");
        var privateKeyFile = new File(TestUtil.DATA_PATH_PREFIX + "private.pem");
        var signer = new Ed25519VerificationMethodKeyProviderImpl(new FileReader(privateKeyFile), new FileReader(publicKeyFile)); // supplied external key pair
        var didLog = TestUtil.buildInitialDidLogEntry(signer);
        var didTdw = DidLogMetaPeeker.peek(didLog).didDocId;
        var didWeb = TrustDidWeb.Companion.read(didTdw, didLog);

        // build JWT using different keys
        var keyPair = com.google.crypto.tink.subtle.Ed25519Sign.KeyPair.newKeyPair();
        var jwk = new com.nimbusds.jose.jwk.OctetKeyPair.Builder(
                com.nimbusds.jose.jwk.Curve.Ed25519,
                com.nimbusds.jose.util.Base64URL.encode(keyPair.getPublicKey()
                ))
                .d(com.nimbusds.jose.util.Base64URL.encode(keyPair.getPrivateKey()))
                .build();

        var publicKeyMultibase = ch.admin.bj.swiyu.didtoolbox.Ed25519Utils.encodeMultibase(keyPair.getPublicKey());
        var keyID = "did:key:" + publicKeyMultibase + "#" + publicKeyMultibase;
        var signedJWT = new com.nimbusds.jwt.SignedJWT(
                new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.Ed25519)
                        .keyID(keyID)
                        .build(),
                new com.nimbusds.jwt.JWTClaimsSet.Builder()
                        .claim("nonce", nonce)
                        .expirationTime(java.util.Date.from(java.time.ZonedDateTime.now().plusDays(1).toInstant()))
                        .build());
        var jwtSigner = new com.nimbusds.jose.crypto.Ed25519Signer(jwk);
        signedJWT.sign(jwtSigner);

        try {
            ProofOfPossessionUtil.verify(signedJWT, nonce, didWeb);
            assert(false);
        } catch (ProofOfPossessionVerificationException e) {
            assertEquals(ProofOfPossessionVerificationException.ErrorCause.KeyNotFoundInDID, e.getErrorCause());
        }
    }

    @Test
    void testVerifyProofOfPossessionUnsupportedAlgorithm() throws ParseException, JOSEException {
        // JWT placeholder from https://www.jwt.io/ using HS256
        var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
        var signedJWT = SignedJWT.parse(jwt);

        try {
            ProofOfPossessionUtil.verify(signedJWT, "", null);
            assert(false);
        } catch (ProofOfPossessionVerificationException e) {
            assertEquals(ProofOfPossessionVerificationException.ErrorCause.UnsupportedAlgorithm, e.getErrorCause());
        }
    }
}
