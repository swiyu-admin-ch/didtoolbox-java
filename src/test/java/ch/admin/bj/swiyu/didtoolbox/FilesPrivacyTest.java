package ch.admin.bj.swiyu.didtoolbox;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import static java.nio.file.attribute.AclEntryPermission.READ_DATA;
import static java.nio.file.attribute.AclEntryPermission.WRITE_DATA;
import static org.junit.jupiter.api.Assertions.*;

class FilesPrivacyTest {

    @Test
    void testCreatePrivateDirectory() {

        AtomicReference<Path> tempDir = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            tempDir.set(Files.createTempDirectory("my-temp-dir-"));
            tempDir.get().toFile().deleteOnExit();
        });

        var dirToCreate = Path.of(tempDir + File.separator + UUID.randomUUID());
        dirToCreate.toFile().deleteOnExit();

        assertDoesNotThrow(() -> {
            FilesPrivacy.createPrivateDirectory(dirToCreate, false); // MUT
        });

        if (Files.getFileAttributeView(dirToCreate, PosixFileAttributeView.class) != null) { // or try relying on POSIX (if the OS implements it)
            assertDoesNotThrow(() -> {
                var perms = Files.getPosixFilePermissions(dirToCreate, NOFOLLOW_LINKS);
                assertFalse((!perms.contains(PosixFilePermission.OWNER_READ) &&
                        !perms.contains(PosixFilePermission.OWNER_WRITE)) ||
                        perms.contains(PosixFilePermission.GROUP_READ) ||
                        perms.contains(PosixFilePermission.GROUP_WRITE) ||
                        perms.contains(PosixFilePermission.OTHERS_READ) ||
                        perms.contains(PosixFilePermission.OTHERS_WRITE)
                );
            });
        }

        var ex = assertThrowsExactly(FileAlreadyExistsException.class, () -> {
            FilesPrivacy.createPrivateDirectory(dirToCreate, false); // MUT
        });
        assertEquals(dirToCreate.toString(), ex.getMessage());

        assertDoesNotThrow(() -> {
            var f = new File(dirToCreate.toFile(), "my-temp-file");
            f.createNewFile();
            f.deleteOnExit();
        });

        var ex1 = assertThrowsExactly(DirectoryNotEmptyException.class, () -> {
            FilesPrivacy.createPrivateDirectory(dirToCreate, true); // MUT
        });
        assertEquals(dirToCreate.toString(), ex1.getMessage());
    }

    @Test
    void testCreatePrivateFile() {

        AtomicReference<Path> tempDir = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            tempDir.set(Files.createTempDirectory("my-temp-dir-"));
            tempDir.get().toFile().deleteOnExit();
        });

        var fileToCreate = Path.of(tempDir + File.separator + UUID.randomUUID());
        fileToCreate.toFile().deleteOnExit();

        AtomicReference<Path> fileCreated = new AtomicReference<>();
        assertDoesNotThrow(() -> {
            fileCreated.set(FilesPrivacy.createPrivateFile(fileToCreate, false)); // MUT
        });

        var path = fileCreated.get();
        assertNotNull(path);
        assertTrue(path.toFile().exists());
        assertTrue(path.toFile().isFile());
        assertFalse(path.toFile().isDirectory());

        if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) { // or try relying on POSIX (if the OS implements it)
            assertDoesNotThrow(() -> {
                var perms = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS);
                assertFalse((!perms.contains(PosixFilePermission.OWNER_READ) &&
                        !perms.contains(PosixFilePermission.OWNER_WRITE)) ||
                        perms.contains(PosixFilePermission.GROUP_READ) ||
                        perms.contains(PosixFilePermission.GROUP_WRITE) ||
                        perms.contains(PosixFilePermission.OTHERS_READ) ||
                        perms.contains(PosixFilePermission.OTHERS_WRITE)
                );
            });
        }

        // make the parent dir "unwritable"
        assertDoesNotThrow(() -> {
            assertNotNull(Files.setPosixFilePermissions(tempDir.get(), PosixFilePermissions.fromString("r--------")));
        });

        var anotherFile = Path.of(tempDir + File.separator + UUID.randomUUID());
        anotherFile.toFile().deleteOnExit();
        AtomicReference<Path> anotherFilePath = new AtomicReference<>();
        var ex = assertThrowsExactly(AccessDeniedException.class, () -> {
            anotherFilePath.set(FilesPrivacy.createPrivateFile(anotherFile, false)); // MUT
        });
        assertNull(anotherFilePath.get());
        assertEquals("The parent directory is not writable", ex.getMessage());

        // cleanup
        assertDoesNotThrow(() -> {
            // make the parent dir "writable" again, so any of the deleteOnExit() calls could actually have effect
            assertNotNull(Files.setPosixFilePermissions(tempDir.get(), PosixFilePermissions.fromString("rwx------")));
        });
    }

    @Test
    void testRestrictAccessToCurrentUserOnly() {
        assertDoesNotThrow(() -> {
            var tempFile = File.createTempFile("my-temp-file", "");
            tempFile.deleteOnExit();

            // reset RW access
            tempFile.setReadable(false);
            tempFile.setWritable(false);

            var tempPath = tempFile.toPath();

            // sanity check
            assertFalse(Files.isReadable(tempPath));
            assertFalse(Files.isWritable(tempPath));

            FilesPrivacy.restrictAccessToCurrentUserOnly(tempFile.toPath()); // MUT

            var aclFileAttributeView = Files.getFileAttributeView(tempPath, AclFileAttributeView.class);
            if (aclFileAttributeView != null) { // try relying on ACL attributes (if any, typically on WIN platforms)

                var currentUserPrincipal = tempPath
                        .getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));

                aclFileAttributeView = Files.getFileAttributeView(tempPath, AclFileAttributeView.class);
                for (AclEntry entry : aclFileAttributeView.getAcl()) {
                    var perms = entry.permissions();

                    if (entry.principal().equals(currentUserPrincipal)) {
                        assertTrue(perms.contains(READ_DATA) && perms.contains(WRITE_DATA));
                        continue;
                    }

                    assertFalse(perms.contains(READ_DATA));
                    assertFalse(perms.contains(WRITE_DATA));
                }

            } else if (Files.getFileAttributeView(tempPath, PosixFileAttributeView.class) != null) { // or try relying on POSIX (if the OS implements it)

                var perms = Files.getPosixFilePermissions(tempPath, NOFOLLOW_LINKS); // may throw SecurityException
                assertFalse((!perms.contains(PosixFilePermission.OWNER_READ) &&
                        !perms.contains(PosixFilePermission.OWNER_WRITE)) ||
                        perms.contains(PosixFilePermission.GROUP_READ) ||
                        perms.contains(PosixFilePermission.GROUP_WRITE) ||
                        perms.contains(PosixFilePermission.OTHERS_READ) ||
                        perms.contains(PosixFilePermission.OTHERS_WRITE)
                );
            }

            assertTrue(Files.isReadable(tempPath));
            assertTrue(Files.isWritable(tempPath));
        });
    }
}