package ch.admin.bj.swiyu.didtoolbox.cli.jcommander;

import ch.admin.bj.swiyu.didtoolbox.cli.CommandException;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class DidLogCommandBaseTest {

    @Test
    void fetchDidLogMeta_contentNeitherPeekerAccepts_throwsCommandExceptionWithPeekerCause(@TempDir Path tmpDir) throws IOException {
        var didLogFile = Files.writeString(tmpDir.resolve("did.jsonl"), "this is not a DID log").toFile();

        var exc = assertThrowsExactly(CommandException.class, () -> DidLogCommandBase.fetchDidLogMeta(didLogFile)); // MUT

        assertTrue(exc.getMessage().contains("unsupported DID log format"), exc.getMessage());
        assertInstanceOf(DidLogMetaPeekerException.class, exc.getCause());
    }

    @Test
    void fetchDidLogMeta_missingFile_throwsCommandExceptionWithIoCause(@TempDir Path tmpDir) {
        var missingFile = tmpDir.resolve("missing.jsonl").toFile();

        var exc = assertThrowsExactly(CommandException.class, () -> DidLogCommandBase.fetchDidLogMeta(missingFile)); // MUT

        assertTrue(exc.getMessage().contains("Failed to read"), exc.getMessage());
        assertInstanceOf(IOException.class, exc.getCause());
    }
}
