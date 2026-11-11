package ch.admin.bj.swiyu.didtoolbox.cli.keymaterial;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.cryptography.PemUtils;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.EdDsaJcs2022VcDataIntegrityCryptographicSuite;
import ch.admin.bj.swiyu.didtoolbox.cryptography.vc_data_integrity.VcDataIntegrityCryptographicSuiteException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
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
    void storeKeysOnDisk_noForceOverwrite_success(@TempDir Path tmpDir) throws Exception {
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
        assertEquals(keys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase());
        assertEquals(keys.getVerificationKeyMultibase(), PemUtils.readEd25519PublicKeyPemFileToMultibase(publicKey.toPath()));
    }

    @Test
    void storeKeysOnDisk_noForceOverwriteAlreadyExists_fails(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, false));

        // Try to store new keys, which must be refused as overwrite mode is not engaged
        var newKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var exc = assertThrowsExactly(CommandException.class, () -> store.storeKeysOnDisk(newKeys, false));
        assertTrue(exc.getMessage().contains("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged"));

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(keys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase()); // should be old keys
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
        assertEquals(keys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase());
    }

    @Test
    void storeKeysOnDisk_withOverwriteAlreadyExisting_success(@TempDir Path tmpDir) throws Exception {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var keys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());

        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(keys, false));

        // Try to store new keys, which replace the existing ones as overwrite mode is engaged
        var newKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        assertDoesNotThrow(() -> store.storeKeysOnDisk(newKeys, true));

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(newKeys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase()); // should be new keys
        var publicKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519.pub");
        assertEquals(newKeys.getVerificationKeyMultibase(), PemUtils.readEd25519PublicKeyPemFileToMultibase(publicKey.toPath())); // should be new keys
    }

    @Test
    @EnabledOnOs({OS.LINUX, OS.MAC})
    void storeKeysOnDisk_freshAndForcedOverwrite_restrictsAccessToCurrentUser(@TempDir Path tmpDir) throws Exception {
        var outputDir = tmpDir.resolve(".didtoolbox");
        var privateKey = outputDir.resolve("id_ed25519");
        var filePermissions = PosixFilePermissions.fromString("rw-------");
        var directoryPermissions = PosixFilePermissions.fromString("rwx------");
        var store = new GeneratedKeyPairStore(outputDir.toString());

        store.storeKeysOnDisk(new EdDsaJcs2022VcDataIntegrityCryptographicSuite(), false); // MUT

        assertEquals(filePermissions, Files.getPosixFilePermissions(privateKey));
        assertEquals(directoryPermissions, Files.getPosixFilePermissions(outputDir));

        // Otherwise, merely writing into the already restricted file would go unnoticed
        Files.setPosixFilePermissions(privateKey, PosixFilePermissions.fromString("rw-r--r--"));

        store.storeKeysOnDisk(new EdDsaJcs2022VcDataIntegrityCryptographicSuite(), true); // MUT

        assertEquals(filePermissions, Files.getPosixFilePermissions(privateKey));
        assertEquals(directoryPermissions, Files.getPosixFilePermissions(outputDir));
    }

    @Test
    void generateAndSaveNewKey_noOverwrite_success(@TempDir Path tmpDir) throws Exception {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        Set<File> keys = new HashSet<>();
        assertDoesNotThrow(() -> store.generateAndSaveNewKey(false, keys));

        var publicKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519.pub");
        assertEquals(Set.of(publicKey), keys); // never the private key file

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), PemUtils.readEd25519PublicKeyPemFileToMultibase(publicKey.toPath()));
    }

    @Test
    void generateAndSaveNewKey_noOverwriteAlreadyExisting_fails(@TempDir Path tmpDir) throws VcDataIntegrityCryptographicSuiteException {
        // Check that .didtoolbox doesn't exist yet
        assertFalse(new File(tmpDir.toString() + File.separator + ".didtoolbox").exists());

        var oldKeys = new EdDsaJcs2022VcDataIntegrityCryptographicSuite();
        var store = new GeneratedKeyPairStore(new File(tmpDir.toString(), ".didtoolbox").getPath());
        // Create filled .didtoolbox directory
        assertDoesNotThrow(() -> store.storeKeysOnDisk(oldKeys, false));

        Set<File> keys = new HashSet<>();
        var exc = assertThrowsExactly(CommandException.class, () -> store.generateAndSaveNewKey(false, keys));
        assertTrue(exc.getMessage().contains("The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged"));
        assertEquals(0, keys.size());

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertEquals(oldKeys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase()); // should be old keys
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

        var publicKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519.pub");
        assertEquals(Set.of(publicKey), keys); // never the private key file

        var privateKey = new File(tmpDir.toString() + File.separator + ".didtoolbox/id_ed25519");
        var cryptoSuite = new EdDsaJcs2022VcDataIntegrityCryptographicSuite(privateKey.toPath());
        assertNotEquals(oldKeys.getVerificationKeyMultibase(), cryptoSuite.getVerificationKeyMultibase()); // keys have changed
        assertEquals(cryptoSuite.getVerificationKeyMultibase(), PemUtils.readEd25519PublicKeyPemFileToMultibase(publicKey.toPath()));
    }
}
