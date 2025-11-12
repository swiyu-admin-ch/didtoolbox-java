package ch.admin.bj.swiyu.didtoolbox.jcommander;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import com.beust.jcommander.IStringConverter;

import java.io.File;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;

public class VerificationMethodParametersConverter implements IStringConverter<List<VerificationMethodParameters>> {
    @Override
    public List<VerificationMethodParameters> convert(String value) {
        String[] splitted = value.split(",");
        List<VerificationMethodParameters> fileList = new ArrayList<>();
        if (splitted.length == 2) {

            String kid = splitted[0];

            String jwk;
            try {

                jwk = JwkUtils.loadECPublicJWKasJSON(new File(splitted[1]), kid);

            } catch (IOException | InvalidKeySpecException e) {
                throw new IllegalArgumentException(e);
            }

            fileList.add(new VerificationMethodParameters(kid, jwk));
        }

        return fileList;
    }
}
