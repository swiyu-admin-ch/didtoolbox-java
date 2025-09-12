package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.jcommander.validator.VerificationMethodKeyParametersValidator;
import com.beust.jcommander.ParameterException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationMethodKeyParametersValidatorTest {
    @Test
    void testValidate() {

        /* A "kid" featuring URIs "Reserved Characters" (incl. "Percent-Encoding") must fail:
        pct-encoded = "%" HEXDIG HEXDIG
        reserved    = gen-delims / sub-delims
        gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
         */
        var validateArgs = new String[][]{ // perhaps using HashSet<String[]> instead?
                {
                        ",some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-%-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-:-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-/-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-?-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-#-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-[-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-]-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-@-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-!-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-$-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-&-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-'-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "my-assert-key-contains-\"-char,some-public-key-file",
                        "option must be a regular case-sensitive string featuring no URIs reserved characters"
                },
                {
                        "no-comma-separator",
                        "should supply a comma-separated list (in format key-name,public-key-file (EC P-256 public/verifying key in PEM format))",
                },
                {
                        "my-assert-key-02,non-existing-file",
                        "option must be a regular file containing EC P-256 public/verifying key in PEM format"
                },
        };

        var validator = new VerificationMethodKeyParametersValidator();
        for (var args : validateArgs) {
            assertThrowsParameterException(() ->
                    validator.validate("irrelevant", args[0]), args[1]
            );
        }
    }

    protected static void assertThrowsParameterException(Executable executable, String containedInErrorMessage) {
        var exc = assertThrowsExactly(ParameterException.class, executable, "Expected: " + containedInErrorMessage);
        if (containedInErrorMessage != null) {
            assertTrue(exc.getMessage().contains(containedInErrorMessage));
        }
    }
}