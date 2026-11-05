package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("PMD")
class GeneratedKeyPairStoreTest {

    @Test
    void constructor_emptyBasePath_fails() {
        assertThrowsExactly(IllegalArgumentException.class, () -> new GeneratedKeyPairStore(""));
    }

    @Test
    void storeKeysOnDisk_noForceOverwrite_success(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();

        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, false));

        assertTrue(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());
        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        assertTrue(privateKey.exists());
        var publicKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519.pub");
        assertTrue(publicKey.exists());

        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), keys.getVerificationKeyMultibase());
    }

    @Test
    void storeKeysOnDisk_noForceOverwriteAlreadyExists_fails(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, false));

        // Try to create new directory
        var newKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        // Returns 1 when something went wrong (files already exists in this case)
        assertThrowsExactly(CommandException.class, () -> store.storeKeysOnDisk(newKeys, false));

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), keys.getVerificationKeyMultibase()); // should be old keys
    }

    @Test
    void storeKeysOnDisk_withOverwrite_success(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, true));

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), keys.getVerificationKeyMultibase()); // should be old keys
    }

    @Test
    void storeKeysOnDisk_withOverwriteAlreadyExisting_success(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());

        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, false));

        // Try to create new directory
        var newKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        // Returns 1 when something went wrong (files already exists in this case)
        assertDoesNotThrow(() -> store.storeKeysOnDisk(newKeys, true));

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), newKeys.getVerificationKeyMultibase()); // should be old keys
    }

    @Test
    void generateAndSaveNewKey_noOverwrite_success(@TempDir Path tmpDir) {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var store = new GeneratedKeyPairStore(tmpDir.toString());
        Set<File> keys = new HashSet<>();
        assertDoesNotThrow(() -> store.generateAndSaveNewKey(false, keys));
        assertEquals(1, keys.size());

        keys.forEach(file -> {
            assertTrue(file.exists());
        });
    }

    @Test
    void generateAndSaveNewKey_noOverwriteAlreadyExisting_fails(@TempDir Path tmpDir) {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var oldKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(oldKeys, false));

        Set<File> keys = new HashSet<>();
        assertThrowsExactly(CommandException.class, () -> store.generateAndSaveNewKey(false, keys));
        assertEquals(0, keys.size());

        keys.forEach(file -> {
            assertTrue(file.exists());
        });
    }

    @Test
    void generateAndSaveNewKey_withOverwrite_success(@TempDir Path tmpDir) throws Exception {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var oldKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());

        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(oldKeys, false));

        Set<File> keys = new HashSet<>();
        assertDoesNotThrow(() -> store.generateAndSaveNewKey(true, keys));
        assertEquals(1, keys.size());

        keys.forEach(file -> {
            assertTrue(file.exists());
        });

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertNotEquals(cryptoSuite.getVerificationKeyMultibase(), oldKeys.getVerificationKeyMultibase()); // keys have changed
    }
}
