package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

class PemUtilsTest {

    @Test
    void testReadEd25519PublicKeyPemFileToMultibase() throws IOException {

        File tempFile = File.createTempFile("mypublickey", ".pem");
        tempFile.deleteOnExit();

        var w = Files.newBufferedWriter(tempFile.toPath());
        w.write("""
                -----BEGIN PUBLIC KEY-----
                MCowBQYDK2VwAyEAURt091SPZZDzKv0Txz9Nhf52jyUxyjqS8CSXbqc0ajk=
                -----END PUBLIC KEY-----
                """);

        w.flush();
        w.close();

        var publicKeyEd25519Multibase = assertDoesNotThrow(() -> {
            return PemUtils.readEd25519PublicKeyPemFileToMultibase(tempFile); // MUT
        });

        assertEquals("z6MkjusMNSk78CNDvFkBsovC71MsB3KRmus572CeZCjRaCgp", publicKeyEd25519Multibase);

        publicKeyEd25519Multibase = assertDoesNotThrow(() -> {
            return PemUtils.readEd25519PublicKeyPemFileToMultibase(new File("src/test/data/public.pem")); // MUT
        });

        assertEquals("z6MkvdAjfVZ2CWa38V2VgZvZVjSkENZpiuiV5gyRKsXDA8UP", publicKeyEd25519Multibase);
    }
}
