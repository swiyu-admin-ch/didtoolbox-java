package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import com.beust.jcommander.internal.DefaultConsole;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests treating the toolbox as a blackbox, running cli commands
 */
class BlackboxIT {

    /**
     * Creates and verifies a proof of possession by first creating a did log.
     * Commands reflect the ones from the README.md
     *
     * @param tempDir temporary directory to store the did log file
     */
    @Test
    void createAndVerifyPoP_thenSuccess(@TempDir Path tempDir) throws Exception {
        var nonce = "nonce";
        var cliOutput = new ByteArrayOutputStream();
        var main = new Main(new DefaultConsole(new PrintStream(cliOutput)));

        // create did
        var argsCreateDidLog = new String[]{"create", "-u", "https://example.com", "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-01,./src/test/data/assert-key-01.pub", "-t", "auth-key-01,./src/test/data/auth-key-01.pub"};
        assertEquals(0, main.run(argsCreateDidLog));
        var didLog = cliOutput.toString();
        cliOutput.reset();

        // store did in file
        var didLogFilePath = tempDir + "/didlog.jsonl";
        try (var writer = new PrintWriter(didLogFilePath, StandardCharsets.UTF_8)) {
            writer.write(didLog);
        }

        // create proof of possession
        var didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc(); // assume a did:webvh log
        didDoc.getId();
        var argsCreatePoP = new String[] {"create-pop", "-d", didLogFilePath, "-k", didDoc.getId() + "#assert-key-01", "-s", "./src/test/data/assert-key-01", "-n", nonce};
        assertEquals(0, main.run(argsCreatePoP));
        var jwt = cliOutput.toString();
        cliOutput.reset();

        // verify proof of possession
        var argsVerifyPoP = new String[] {"verify-pop", "-d", didLogFilePath, "-n", nonce, "-j", jwt};
        assertEquals(0, main.run(argsVerifyPoP));
        var out = cliOutput.toString();
        assertTrue(out.contains("JWT is valid"));
    }

    /**
     * Creates, updates and deactivates a did log, ensuring common did operations work.
     *
     * @param tempDir temporary directory to store the did log files
     */
    @Test
    void createUpdateAndDeactivateDidLog_thenFailUpdate(@TempDir Path tempDir) throws Exception {
        var cliOutput = new ByteArrayOutputStream();
        var main = new Main(new DefaultConsole(new PrintStream(cliOutput)));

        // create did
        var argsCreateDidLog = new String[]{"create", "-u", "https://example.com", "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-01,./src/test/data/assert-key-01.pub", "-t", "auth-key-01,./src/test/data/auth-key-01.pub"};
        assertEquals(0, main.run(argsCreateDidLog));
        var didLog = cliOutput.toString();
        cliOutput.reset();

        // assert did doc contains keys
        var didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc();
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#auth-key-01"));
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#assert-key-01"));

        // store did in file
        var didLogFilePathV1 = tempDir.toString() + "/didlogV1.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV1, StandardCharsets.UTF_8)) {
            writer.write(didLog);
        }

        // update did
        var updateDidLog = new String[]{"update", "-d", didLogFilePathV1, "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-02,./src/test/data/assert-key-01.pub", "-t", "auth-key-02,./src/test/data/auth-key-01.pub"};
        assertEquals(0, main.run(updateDidLog));
        didLog = cliOutput.toString();
        cliOutput.reset();

        // assert did doc contains updated keys
        didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc();
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#auth-key-02"));
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#assert-key-02"));

        var didLogFilePathV2 = tempDir + "/didlogV2.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV2, StandardCharsets.UTF_8)) {
            writer.write(didLog);
        }

        // deactivate did log
        var deactivateDidLog = new String[]{"deactivate", "-d", didLogFilePathV2, "-s", "./src/test/data/private.pem"};
        assertEquals(0, main.run(deactivateDidLog));
        didLog = cliOutput.toString();
        cliOutput.reset();

        // FIXME: the current didresolver does not yet throw an exception when trying to resolve a deactivated did.
        // The below line should work once the didresolver exhibits the desired behavior.
        // assertThrows(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(didLog), DidLogMetaPeekerException.class);
        // Current workaround is to try and update a deactivated did log, which fails.
        var didLogFilePathV3 = tempDir + "/didlogV3.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV3, StandardCharsets.UTF_8)) {
            writer.write(didLog);
        }
        var updateDeactivatedDidLog = new String[]{"update", "-d", didLogFilePathV3, "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-03,./src/test/data/assert-key-01.pub", "-t", "auth-key-03,./src/test/data/auth-key-01.pub"};
        assertEquals(1, main.run(updateDeactivatedDidLog));
        var out = cliOutput.toString();
        assertTrue(out.contains("can no longer be updated"));
    }
}