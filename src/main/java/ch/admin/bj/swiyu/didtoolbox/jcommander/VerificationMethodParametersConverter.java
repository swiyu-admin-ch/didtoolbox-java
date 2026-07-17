package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import com.beust.jcommander.IStringConverter;

import java.io.IOException;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class VerificationMethodParametersConverter implements IStringConverter<List<VerificationMethodParameters>> {
    @Override
    public List<VerificationMethodParameters> convert(String value) {
        List<VerificationMethodParameters> fileList = new ArrayList<>();

        String[] split = value.split(",");
        if (split.length == 2) { //NOPMD AvoidLiteralsInIfCondition
            String kid = split[0];

            String jwk;
            try {
                jwk = JwkUtils.loadECPublicJWKasJSON(Path.of(split[1]), kid);
            } catch (IOException e) {
                throw new IllegalArgumentException(e);
            }

            fileList.add(new VerificationMethodParameters(kid, jwk));
        }

        return fileList;
    }
}
