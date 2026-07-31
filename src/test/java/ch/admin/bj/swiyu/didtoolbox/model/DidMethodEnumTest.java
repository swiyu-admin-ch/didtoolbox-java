package ch.admin.bj.swiyu.didtoolbox.model;

import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.junit.jupiter.api.Assertions.*;

public class DidMethodEnumTest {

    @Test
    void parse_null_returnsNull() {
        var version = assertDoesNotThrow(() -> DidMethodEnum.parse(null));
        assertEquals(null, version);
    }

    @Test
    void parse_tdwMixedCase_returnsTdw() {
        var tdwStrig = "dId:TDw:0.3";
        var version = assertDoesNotThrow(() -> DidMethodEnum.parse(tdwStrig));
        assertEquals(DidMethodEnum.TDW_0_3, version);
    }

    @Test
    void parse_webvhMixedCase_returnsTdw() {
        var webvhString = "DiD:wEBvH:1.0";
        var version = assertDoesNotThrow(() -> DidMethodEnum.parse(webvhString));
        assertEquals(DidMethodEnum.WEBVH_1_0, version);
    }

    @Test
    void parse_tdwWithWrongVersion_returnsTdw() {
        var tdwString = "DiD:tDw:1.0";
        assertThrowsExactly(ParseException.class, () -> DidMethodEnum.parse(tdwString));
    }

    @Test
    void parse_webvhWithWrongVersion_returnsTdw() {
        var webvhString = "DiD:wEBvH:0.3";
        assertThrowsExactly(ParseException.class, () -> DidMethodEnum.parse(webvhString));
    }

    @Test
    void isTdw03() {
        assertTrue(DidMethodEnum.TDW_0_3.isTdw03());
        assertFalse(DidMethodEnum.WEBVH_1_0.isTdw03());
    }

    @Test
    void isWebv10() {
        assertFalse(DidMethodEnum.TDW_0_3.isWebVh10());
        assertTrue(DidMethodEnum.WEBVH_1_0.isWebVh10());
    }

    @Test
    void detectDidMethod_withValidTdwLog_returnsTdw() {
        var tdw = """
                ["1-QmRVQ8EFiYfGqLXTpHSYMYXMcpFZwsy58gBeFYBEG3RPgj","2026-07-27T05:13:16Z",{"method":"did:tdw:0.3","scid":"QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC","updateKeys":["z6MkffRFEaq5wypbXTNK7AvmhvTWf4XiKVLomouvkpjuRPmP"],"portable":false},{"value":{"id":"did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com","authentication":["did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com#auth-key-01"],"assertionMethod":["did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com#assert-key-01"],"verificationMethod":[{"id":"did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com#auth-key-01","controller":"did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"auth-key-01","x":"5mEj0G8RrCIK6Y-LFN0XAwEpRwhvyqwuqZ-4yQp6p4U","y":"q5-z3xdICaa7hTAfc-0HTiyR-5XklJTsjfcKWG9tGaw"}},{"id":"did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com#assert-key-01","controller":"did:tdw:QmY8Qa5YJynh7syyaUuBYSBJX18DjuYZ2BKsYBXoAv2VeC:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"EC","crv":"P-256","kid":"assert-key-01","x":"bwUStKHLIRy3RN1lyqgOdgTXO8h80KfcbGIZdn0wzEY","y":"JJG7jrkfY8PpW_yjHMJoB8GbuXpZWdPGX06vGAJlfOY"}}]}},[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-07-27T05:13:16Z","verificationMethod":"did:key:z6MkffRFEaq5wypbXTNK7AvmhvTWf4XiKVLomouvkpjuRPmP#z6MkffRFEaq5wypbXTNK7AvmhvTWf4XiKVLomouvkpjuRPmP","proofPurpose":"authentication","challenge":"1-QmRVQ8EFiYfGqLXTpHSYMYXMcpFZwsy58gBeFYBEG3RPgj","proofValue":"z5SjoNbsuT8z7WTvhVFWtLA8HNiteaQVsViYktcQ9EBtBaXEzqpbSCUSnqBw8io7MmLJMYy2Y3L9CAw7FySzWGoLs"}]]
                """;
        var version = assertDoesNotThrow(() -> DidMethodEnum.detectDidMethod(tdw));
        assertEquals(DidMethodEnum.TDW_0_3, version);
    }

    @Test
    void detectDidMethod_withValidWebvhLog_returnsWebvh() {
        var webvh = """
                {"versionId":"1-QmRYUsgbt7VLoNNWoG2KNAjTHgiRVXGMTJZ2arPAp54HZv","versionTime":"2026-07-27T05:11:17Z","parameters":{"method":"did:webvh:1.0","scid":"QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW","updateKeys":["z6MkhcZ1SvznbP5SdGqDXFJeZWtMebj9sFvk7VdLVBwBs57Z"],"portable":false},"state":{"id":"did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com","profile_version":"swiss-profile-anchor:1.0.0","authentication":["did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com#auth-key-01"],"assertionMethod":["did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com#assert-key-01"],"verificationMethod":[{"id":"did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com#auth-key-01","controller":"did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"pKBaly1Q4Ef6ZQDLmMHYYM40JvdvsBSEmUrqD6AxUeE","kid":"auth-key-01"}},{"id":"did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com#assert-key-01","controller":"did:webvh:QmNZxwVtNp68iTXdZUwjMMqyPS7Xj5JTZpr424whqkLXyW:example.com","type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AAuX9zdzGa2lm8NgLGpDm0iwDEfhjf3t7yMGhrJYkEQ","kid":"assert-key-01"}}]},"proof":[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-07-27T05:11:17Z","verificationMethod":"did:key:z6MkhcZ1SvznbP5SdGqDXFJeZWtMebj9sFvk7VdLVBwBs57Z#z6MkhcZ1SvznbP5SdGqDXFJeZWtMebj9sFvk7VdLVBwBs57Z","proofPurpose":"assertionMethod","proofValue":"z26ATsdLQXp2kBSCEPwSyasGChdqUJJ6gaHmQbzrrXSSjxoauL5SxqgKwNpa51WLQ1GwbgG2k3nccbbDtpgi5AsxA"}]}
                """;
        var version = assertDoesNotThrow(() -> DidMethodEnum.detectDidMethod(webvh));
        assertEquals(DidMethodEnum.WEBVH_1_0, version);
    }

    @Test
    void detectDidMethod_nonDidLogJson_throws() {
        var json = """
                {"foo": "bar", "numbers: [1,2,3,4,5]}
                """;
        assertThrowsExactly(DidLogMetaPeekerException.class, () -> DidMethodEnum.detectDidMethod(json));
    }

    @Test
    void detectDidMethod_ofNull_throwsNullPointerException() {
        String didLog = null;
        assertThrowsExactly(NullPointerException.class,() -> DidMethodEnum.detectDidMethod(didLog));
    }
}
