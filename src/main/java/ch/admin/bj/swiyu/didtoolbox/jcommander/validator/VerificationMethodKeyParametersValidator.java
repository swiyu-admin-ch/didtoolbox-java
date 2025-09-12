package ch.admin.bj.swiyu.didtoolbox.jcommander.validator;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import com.beust.jcommander.IParameterValidator;
import com.beust.jcommander.ParameterException;

import java.io.File;

public class VerificationMethodKeyParametersValidator implements IParameterValidator {
    @Override
    public void validate(String name, String value) throws ParameterException {
        String[] splitted = value.split(",");
        if (splitted.length != 2) {
            throw new ParameterException("Option " + name + " should supply a comma-separated list (in format key-name,public-key-file (EC P-256 public/verifying key in PEM format)) (found " + value + ")");
        }

        String kid = splitted[0];
        // Prevent any "kid" featuring URIs "Reserved Characters" (incl. "Percent-Encoding", see (https://datatracker.ietf.org/doc/html/rfc3986#section-2.2):
        //     pct-encoded = "%" HEXDIG HEXDIG
        //     reserved    = gen-delims / sub-delims
        //     gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
        //     sub-delims  = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
        // A case-sensitive "kid" string may contain URIs "Unreserved Characters" (https://datatracker.ietf.org/doc/html/rfc3986#section-2.3) though:
        //     unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
        if (!kid.matches("[a-zA-Z0-9~._-]+")) {
            throw new ParameterException("The key ID (kid) of the JWK supplied by " + name + " option must be a regular case-sensitive string featuring no URIs reserved characters (found " + kid + ")");
        }

        String jwkFile = splitted[1];
        File f = new File(jwkFile);
        if (!f.exists() || !f.isFile()) {
            throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must be a regular file containing EC P-256 public/verifying key in PEM format (found " + jwkFile + ")");
        }

        try {
            JwkUtils.loadECPublicJWKasJSON(f, kid);
            //} catch (IOException | InvalidKeySpecException e) {
        } catch (Exception e) {
            throw new ParameterException("A public key file (" + jwkFile + ") supplied by " + name + " option must contain an EC P-256 public/verifying key in PEM format: " + e.getLocalizedMessage());
        }
    }
}
