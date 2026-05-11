package ch.admin.bj.swiyu.didtoolbox;

import ch.admin.bj.swiyu.didtoolbox.model.WebVerifiableHistoryDidLogMetaPeeker;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static ch.admin.bj.swiyu.didtoolbox.Main.*;
import static org.junit.jupiter.api.Assertions.*;

class E2ECommandTest {

    @Test
    void testPoPCreationAndVerification() throws Exception {
        var nonce = "nonce";
        var stdout = new ByteArrayOutputStream();
        System.setOut(new PrintStream(stdout)); // capture standard out
        File tmpdir = Files.createTempDirectory("pop_test").toFile();

        // create did
        var argsCreateDidLog = new String[]{"create", "-u", "https://example.com", "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-01,./src/test/data/assert-key-01.pub", "-t", "auth-key-01,./src/test/data/auth-key-01.pub"};
        main(argsCreateDidLog);
        var didLog = stdout.toString();
        stdout.reset();

        // store did in file
        var didLogFilePath = tmpdir.getAbsolutePath() + "/didlog.jsonl";
        try (var writer = new PrintWriter(didLogFilePath, StandardCharsets.UTF_8)) {
            writer.write(didLog);
        }

        // create proof of possession
        var didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc(); // assume a did:webvh log
        didDoc.getId();
        var argsCreatePoP = new String[] {"create-pop", "-d", didLogFilePath, "-k", didDoc.getId() + "#assert-key-01", "-s", "./src/test/data/assert-key-01", "-n", nonce};
        main(argsCreatePoP);
        var jwt = stdout.toString();
        stdout.reset();

        // verify proof of possession
        var argsVerifyPoP = new String[] {"verify-pop", "-d", didLogFilePath, "-n", nonce, "-j", jwt};
        main(argsVerifyPoP);
        var out = stdout.toString();
        assertTrue(out.contains("JWT is valid"));
        tmpdir.deleteOnExit();
    }

    @Test
    void testWebvhCreateUpdateAndDeactivate() throws Exception {
        var stdout = new ByteArrayOutputStream();
        System.setOut(new PrintStream(stdout)); // capture standard out
        File tmpdir = Files.createTempDirectory("didwebvh_test").toFile();

        // create did
        var argsCreateDidLog = new String[]{"create", "-u", "https://example.com", "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-01,./src/test/data/assert-key-01.pub", "-t", "auth-key-01,./src/test/data/auth-key-01.pub"};
        main(argsCreateDidLog);
        var didLog = stdout.toString();
        stdout.reset();

        // assert did doc contains keys
        var didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc();
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#auth-key-01"));
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#assert-key-01"));

        // store did in file
        var didLogFilePathV1 = tmpdir.getAbsolutePath() + "/didlogV1.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV1, "UTF-8")) {
            writer.write(didLog);
        }

        // update did
        var updateDidLog = new String[]{"update", "-d", didLogFilePathV1, "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-02,./src/test/data/assert-key-01.pub", "-t", "auth-key-02,./src/test/data/auth-key-01.pub"};
        main(updateDidLog);
        didLog = stdout.toString();
        stdout.reset();

        // assert did doc contains updated keys
        didDoc = WebVerifiableHistoryDidLogMetaPeeker.peek(didLog).getDidDoc();
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#auth-key-02"));
        assertNotNull(didDoc.getKeyByMethodId(didDoc.getId() + "#assert-key-02"));

        var didLogFilePathV2 = tmpdir.getAbsolutePath() + "/didlogV2.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV2, "UTF-8")) {
            writer.write(didLog);
        }

        // deactivate did log
        var deactivateDidLog = new String[]{"deactivate", "-d", didLogFilePathV2, "-s", "./src/test/data/private.pem"};//, "-v",  "./src/test/data/public.pem"};
        main(deactivateDidLog);
        didLog = stdout.toString();
        stdout.reset();

        // Current didresolver does not yet throw exception when trying to resolve a deactivated did.
        // TODO: update test to check deactivation through exception, line below
        // assertThrows(() -> WebVerifiableHistoryDidLogMetaPeeker.peek(didLog), DidLogMetaPeekerException.class);

        // Fails to update deactivated did log because there are no updatekeys, causing a nullpointer when trying to access them.
        var didLogFilePathV3 = tmpdir.getAbsolutePath() + "/didlogV3.jsonl";
        try (var writer = new PrintWriter(didLogFilePathV3, "UTF-8")) {
            writer.write(didLog);
        }
        var updateDidLog2 = new String[]{"update", "-d", didLogFilePathV3, "-s", "./src/test/data/private.pem", "-v", "./src/test/data/public.pem", "-a", "assert-key-03,./src/test/data/assert-key-01.pub", "-t", "auth-key-03,./src/test/data/auth-key-01.pub"};
        assertThrows(NullPointerException.class, () -> main(updateDidLog2));
    }
}
