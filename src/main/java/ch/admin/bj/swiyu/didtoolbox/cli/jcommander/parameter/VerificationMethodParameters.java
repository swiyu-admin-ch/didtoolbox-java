package ch.admin.bj.swiyu.didtoolbox.cli.jcommander.parameter;

public class VerificationMethodParameters {

    public final String key;
    public final String jwk;

    public VerificationMethodParameters(String key, String jwk) {
        this.key = key;
        this.jwk = jwk;
    }
}
