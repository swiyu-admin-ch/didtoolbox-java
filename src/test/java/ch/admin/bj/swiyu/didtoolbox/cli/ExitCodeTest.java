package ch.admin.bj.swiyu.didtoolbox.cli;

import ch.admin.bj.swiyu.didtoolbox.cryptography.primus.PrimusKeyStoreInitializationException;
import ch.admin.bj.swiyu.didtoolbox.did.DidLogMetaPeekerException;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;

import java.io.FileNotFoundException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExitCodeTest {

    @Test
    void testOf() {
        assertEquals(ExitCode.USAGE, ExitCode.of(new ParameterException("invalid")));
        assertEquals(ExitCode.USAGE, ExitCode.of(new JCommanderRunner.CommandException("no keys")));
        assertEquals(ExitCode.IO_ENVIRONMENT, ExitCode.of(new ParameterException("missing", new FileNotFoundException())));
        assertEquals(ExitCode.IO_ENVIRONMENT, ExitCode.of(new ParameterException("hsm", new PrimusKeyStoreInitializationException("unreachable"))));
        assertEquals(ExitCode.CRYPTO_VERIFICATION, ExitCode.of(new ParameterException("malformed", new InvalidKeySpecException())));
        assertEquals(ExitCode.CRYPTO_VERIFICATION, ExitCode.of(new JCommanderRunner.CommandException("unsupported", new DidLogMetaPeekerException("malformed"))));
        assertEquals(ExitCode.UNEXPECTED, ExitCode.of(new IllegalStateException()));
        assertEquals(ExitCode.UNEXPECTED, ExitCode.of(new Exception()));
        assertEquals(ExitCode.UNEXPECTED, ExitCode.of(null));
    }
}
