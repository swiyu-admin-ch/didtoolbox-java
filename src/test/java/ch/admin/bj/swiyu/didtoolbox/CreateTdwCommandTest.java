package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.JCommander;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

public class CreateTdwCommandTest {

    final String DEFAULT_KEY_PAIR_OUTPUT_DIR = ".didtoolbox";

    private static Stream<Arguments> outputDirectoryRequiredKeyPairOutputDirectoryCmdLineParams() {
        return Stream.of(
                arguments((Object) new String[] {"-u", "https://example.com"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--jks-file", "src/test/data/mykeystore.jks"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--signing-key-file", "src/test/data/private.pem"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--verifying-key-file", "src/test/data/public.pem"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--signing-key-file", "src/test/data/private.pem", "--verifying-key-file", "src/test/data/public.pem"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--assert", "assert-key-01,src/test/data/assert-key-01.pub"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--auth", "auth-key-01,src/test/data/auth-key-01.pub"})
        );
    }

    private static Stream<Arguments> notOutputDirectoryRequiredKeyPairOutputDirectoryCmdLineParams() {
        return Stream.of(
                arguments((Object) new String[] {"-u", "https://example.com", "--jks-file", "src/test/data/mykeystore.jks", "--assert", "assert-key-01,src/test/data/assert-key-01.pub", "--auth", "auth-key-01,src/test/data/auth-key-01.pub"}),
                arguments((Object) new String[] {"-u", "https://example.com", "--signing-key-file", "src/test/data/private.pem", "--verifying-key-file", "src/test/data/public.pem", "--assert", "assert-key-01,src/test/data/assert-key-01.pub", "--auth", "auth-key-01,src/test/data/auth-key-01.pub"})
                );
    }

    @BeforeEach
    void deleteKeyPairOutputDirectory() throws IOException {
        final Path DIRECTORY_TO_DELETE = Paths.get(DEFAULT_KEY_PAIR_OUTPUT_DIR);
        if (Files.exists(DIRECTORY_TO_DELETE)) {
            Files.walkFileTree(DIRECTORY_TO_DELETE, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException, IOException {
                    Files.delete(file); // Delete the file
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir); // Delete the directory after its contents are deleted
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    @DisplayName("No key pairs need to be generated (no output directory required)")
    @ParameterizedTest(name = "For arguments: {0}")
    @MethodSource("notOutputDirectoryRequiredKeyPairOutputDirectoryCmdLineParams")
    void testKeyPairOutputDirectoryParametersValidatorNoOutputDirectoryRequired(String[] cmdLineParams) {
        final File keyPairOutputDir = new File(DEFAULT_KEY_PAIR_OUTPUT_DIR);
        assumeTrue(keyPairOutputDir.mkdirs(), "unable to create directory: " + keyPairOutputDir.getAbsolutePath());
        JCommander jc = JCommander.newBuilder()
                .addObject(new CreateTdwCommand())
                .build();
        jc.parse(cmdLineParams);
    }

    @DisplayName("Key pair(s) need to be generated, prevent overwriting existing ones (fail if output directory exists)")
    @ParameterizedTest(name = "For arguments: {0}")
    @MethodSource("outputDirectoryRequiredKeyPairOutputDirectoryCmdLineParams")
    void testKeyPairOutputDirectoryParametersValidatorOutputDirectoryRequired(String[] cmdLineParams) {
        final File keyPairOutputDir = new File(DEFAULT_KEY_PAIR_OUTPUT_DIR);
        assumeTrue(keyPairOutputDir.mkdirs(), "unable to create directory: " + keyPairOutputDir.getAbsolutePath());
        JCommander jc = JCommander.newBuilder()
                .addObject(new CreateTdwCommand())
                .build();
        Exception exception = assertThrows(com.beust.jcommander.ParameterException.class, () -> jc.parse(cmdLineParams));
        assertTrue(exception.getMessage().contains("Rename or move it to prevent from overwriting of previously generated key material"));
    }

}
