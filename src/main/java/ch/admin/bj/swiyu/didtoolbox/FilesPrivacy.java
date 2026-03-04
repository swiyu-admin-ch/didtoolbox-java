package ch.admin.bj.swiyu.didtoolbox;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * A convenient helper introduced for the sake of comfortably restricting access to any file or a directory,
 * regardless of the underlying file system.
 */
final class FilesPrivacy {
    private FilesPrivacy() {
    }

    private final static Set<PosixFilePermission> POSIX_FILE_PERM_OWNER_READ_WRITE_EXEC = PosixFilePermissions.fromString("rwx------");

    private final static Set<PosixFilePermission> POSIX_FILE_PERM_OWNER_READ_WRITE = PosixFilePermissions.fromString("rw-------");

    private final static Set<AclEntryPermission> ACL_PERMISSIONS_FULL_CONTROL = EnumSet.of(
            // Permission to read the data of the file.
            AclEntryPermission.READ_DATA,

            // Permission to modify the file's data.
            AclEntryPermission.WRITE_DATA,

            // Permission to append data to a file.
            AclEntryPermission.APPEND_DATA,

            // Permission to read the named attributes of a file.
            AclEntryPermission.READ_NAMED_ATTRS,

            // Permission to write the named attributes of a file.
            AclEntryPermission.WRITE_NAMED_ATTRS,

            // Permission to execute a file.
            AclEntryPermission.EXECUTE,

            // Permission to delete a file or directory within a directory.
            AclEntryPermission.DELETE_CHILD,

            // The ability to read (non-acl) file attributes.
            AclEntryPermission.READ_ATTRIBUTES,

            // The ability to write (non-acl) file attributes.
            AclEntryPermission.WRITE_ATTRIBUTES,

            // Permission to delete the file.
            AclEntryPermission.DELETE,

            // Permission to read the ACL attribute.
            AclEntryPermission.READ_ACL,

            // Permission to write the ACL attribute.
            AclEntryPermission.WRITE_ACL,

            // Permission to change the owner.
            AclEntryPermission.WRITE_OWNER,

            // Permission to access file locally at the server with synchronous reads and writes.
            AclEntryPermission.SYNCHRONIZE,

            // Permission to list the entries of a directory (equal to {@link #READ_DATA})
            AclEntryPermission.LIST_DIRECTORY,

            // Permission to add a new file to a directory (equal to {@link #WRITE_DATA})
            AclEntryPermission.ADD_FILE,

            // Permission to create a subdirectory to a directory (equal to {@link #APPEND_DATA})
            AclEntryPermission.ADD_SUBDIRECTORY
    );

    final private static EnumSet<AclEntryFlag> ALL_ACL_FLAGS = EnumSet.of(
            // Can be placed on a directory and indicates that the ACL entry should be added to each new non-directory file created.
            AclEntryFlag.FILE_INHERIT,
            // Can be placed on a directory and indicates that the ACL entry should be added to each new directory created.
            AclEntryFlag.DIRECTORY_INHERIT
            // Can be placed on a directory but does not apply to the directory, only to newly created files/directories as specified by the FILE_INHERIT and DIRECTORY_INHERIT flags.
            // AclEntryFlag.INHERIT_ONLY,
    );

    private static UserPrincipal getCurrentUserPrincipal(Path path) {

        try {
            if (path != null) {
                return path.getFileSystem()
                        .getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));
            }

            return FileSystems.getDefault()
                    .getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));

        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Creates a new directory just as {@link Files#createDirectory(Path, FileAttribute[])} would do,
     * only with access restricted the current user.
     *
     * @param path  the directory to create
     * @param force to denote enforcement of the directory creation, hance that the directory deletion takes place prior to creation.
     *              Regardless of its value, it will always be taken into account whether the parent (directory) is "writable" or not
     * @throws DirectoryNotEmptyException    (in case {@code force} is engaged) if the file is a directory and could not otherwise be deleted
     *                                       because the directory is not empty <i>(optional specific
     *                                       exception)</i>
     * @throws FileAlreadyExistsException    (in case {@code force} is NOT engaged) if a directory could not otherwise be created because a file of
     *                                       that name already exists <i>(optional specific exception)</i>
     * @throws UnsupportedOperationException if the array contains an attribute that cannot be set atomically
     *                                       when creating the directory
     * @throws IOException                   if an I/O error occurs or the parent directory does not exist
     * @throws SecurityException             In the case of the default provider, and a security manager is
     *                                       installed, the SecurityManager#checkWrite(String)
     *                                       method is invoked to check write access to the new directory.
     * @see Files#deleteIfExists(Path)
     * @see Files#createDirectory(Path, FileAttribute[])
     */
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    static void createPrivateDirectory(Path path, boolean force) throws IOException {

        // Regardless of force flag, always take into account whether the parent directory is "writable" or not
        if (null != path.getParent() && !Files.isWritable(path.getParent())) { // may throw SecurityException
            throw new AccessDeniedException("The parent directory is not writable");
        }

        if (force) {
            // CAUTION The return value is ignored intentionally as irrelevant
            Files.deleteIfExists(path); // may throw DirectoryNotEmptyException, AccessDeniedException, SecurityException etc.
        }

        var os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win") || null != Files.getFileAttributeView(path, AclFileAttributeView.class)) {

            Files.createDirectory(path, new FileAttribute<List<AclEntry>>() {

                @Override
                public List<AclEntry> value() {

                    var aclEntryList = new ArrayList<AclEntry>();
                    aclEntryList.add(AclEntry.newBuilder()
                            .setType(
                                    // Explicitly grants access to a file or directory.
                                    AclEntryType.ALLOW)
                            .setFlags(ALL_ACL_FLAGS)
                            // lookup current user principal
                            .setPrincipal(getCurrentUserPrincipal(null))
                            .setPermissions(ACL_PERMISSIONS_FULL_CONTROL)
                            .build());

                    return aclEntryList;
                }

                @Override
                public String name() {
                    return "acl:acl";
                }
            });
            return;

        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")
                || os.contains("mac") || os.contains("darwin")) {

            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(POSIX_FILE_PERM_OWNER_READ_WRITE_EXEC));
            return;
        }

        throw new IllegalArgumentException("Unsupported operating system: " + os);
    }

    /**
     * Creates a new and empty file, failing if the file already exists.
     * It behaves the same way as {@link Files#createFile(Path, FileAttribute[])},
     * only with access restricted the current user.
     *
     * @param path  the path to the file to create
     * @param force to denote enforcement of the file creation, hance that the file deletion takes place prior to creation.
     *              Regardless of its value, it will always be taken into account whether the parent (directory) is "writable" or not
     * @return the file
     * @throws DirectoryNotEmptyException    (in case {@code force} is engaged) if the file is a directory and could not otherwise be deleted
     *                                       because the directory is not empty <i>(optional specific
     *                                       exception)</i>
     * @throws FileAlreadyExistsException    (in case {@code force} is NOT engaged) If a file of that name already exists
     *                                       <i>(optional specific exception)</i>
     * @throws UnsupportedOperationException if the array contains an attribute that cannot be set atomically
     *                                       when creating the file
     * @throws IOException                   if an I/O error occurs or the parent directory does not exist
     * @throws SecurityException             In the case of the default provider, and a security manager is
     *                                       installed, the SecurityManager#checkWrite(String)
     *                                       method is invoked to check write access to the new file.
     * @see Files#deleteIfExists(Path)
     * @see Files#createFile(Path, FileAttribute[])
     */
    @SuppressWarnings({"PMD.CyclomaticComplexity"})
    static Path createPrivateFile(Path path, boolean force) throws IOException {

        // Regardless of force flag, always take into account whether the parent directory is "writable" or not
        if (null != path.getParent() && !Files.isWritable(path.getParent())) { // may throw SecurityException
            throw new AccessDeniedException("The parent directory is not writable");
        }

        if (force) {
            // CAUTION The return value is ignored intentionally as irrelevant
            Files.deleteIfExists(path); // may throw DirectoryNotEmptyException, AccessDeniedException, SecurityException etc.
        }

        var os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win") || null != Files.getFileAttributeView(path, AclFileAttributeView.class)) {

            return Files.createFile(path, new FileAttribute<List<AclEntry>>() {

                @Override
                public List<AclEntry> value() {

                    var aclEntryList = new ArrayList<AclEntry>();
                    aclEntryList.add(AclEntry.newBuilder()
                            .setType(
                                    // Explicitly grants access to a file or directory.
                                    AclEntryType.ALLOW)
                            .setFlags(ALL_ACL_FLAGS)
                            // lookup current user principal
                            .setPrincipal(getCurrentUserPrincipal(null))
                            .setPermissions(ACL_PERMISSIONS_FULL_CONTROL)
                            .build());

                    return aclEntryList;
                }

                @Override
                public String name() {
                    return "acl:acl";
                }
            });

        } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")
                || os.contains("mac") || os.contains("darwin")) {

            return Files.createFile(path, PosixFilePermissions.asFileAttribute(POSIX_FILE_PERM_OWNER_READ_WRITE));

        }

        throw new IllegalArgumentException("Unsupported operating system: " + os);
    }

    /**
     * The helper ensures that access rights (to supplied path) are exclusively restricted to the current user.
     *
     * @param path the path to the file
     * @throws IOException       if an I/O error occurs or the ACL is invalid
     * @throws SecurityException In the case of the default provider, and a security manager is
     *                           installed, it denies
     *                           {@link RuntimePermission}{@code ("accessUserInformation")}
     *                           or its "checkWrite" method denies write access to the file.
     */
    static void restrictAccessToCurrentUserOnly(Path path) throws IOException {

        if (!path.toFile().exists()) {
            throw new IllegalArgumentException("The file denoted by path does not exist: " + path);
        }

        var aclFileAttributeView = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (aclFileAttributeView != null) { // try relying on ACL attributes (if any, typically on WIN platforms)

            var currentUserPrincipal = getCurrentUserPrincipal(path);

            // create ACE to give current user READ access
            var aclEntry = AclEntry.newBuilder()
                    .setType(
                            // Explicitly grants access to a file or directory.
                            AclEntryType.ALLOW)
                    .setFlags(ALL_ACL_FLAGS)
                    .setPrincipal(currentUserPrincipal)
                    .setPermissions(ACL_PERMISSIONS_FULL_CONTROL)
                    .build();

            // read (and clear) ACL, insert ACE, re-write ACL
            var acl = aclFileAttributeView.getAcl(); // may throw SecurityException
            acl.clear();
            acl.add(0, aclEntry);
            aclFileAttributeView.setOwner(currentUserPrincipal); // may throw SecurityException
            aclFileAttributeView.setAcl(acl); // may throw SecurityException

        } else if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) { // or try relying on POSIX (if the OS implements it)

            Files.setPosixFilePermissions(path, POSIX_FILE_PERM_OWNER_READ_WRITE_EXEC); // may throw SecurityException

        } else { // fallback

            // CAUTION If the underlying file system can not distinguish the owner's read permission from that of others,
            //         then the permission will apply to everybody, regardless of this value.
            if (!path.toFile().setReadable(true)) { // ownerOnly = true, may throw SecurityException
                throw new IOException("Failed to set the owner's read permission for file: " + path);
            }
            if (!path.toFile().setWritable(true)) { // ownerOnly = true, may throw SecurityException
                throw new IOException("Failed to set the owner's write permission for file: " + path);
            }
        }
    }
}
