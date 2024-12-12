package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import java.io.FileInputStream;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(String... args) {

        var createCommand = new CreateTdwCommand();
        var jc = JCommander.newBuilder()
                .addCommand("create", createCommand)
                .build();

        try {
            jc.parse(args);
        } catch (ParameterException e) {
            System.err.println(e.getLocalizedMessage());
            jc.usage();
            System.exit(1);
        }

        var parsedCmdStr = jc.getParsedCommand();
        if (parsedCmdStr == null) {
            jc.usage();
            System.exit(1);
        }

        switch (parsedCmdStr) {

            case "create":

                var domain = createCommand.domain;
                var path = createCommand.path;

                var assertions = createCommand.assertions;
                Map<String, AssertionMethodInput> assertionMethodsMap = new HashMap<>();
                for (CreateTdwCommand.AssertionMethodParameters param : assertions) {
                    assertionMethodsMap.put(param.key, new AssertionMethodInput(param.publicKeyMultibase));
                }

                var signingKeyPemFile = createCommand.signingKeyPemFile;
                var verifyingKeyPemFile = createCommand.verifyingKeyPemFile;

                var jksFile = createCommand.jksFile;
                var jksPassword = createCommand.jksPassword;
                var jksAlias = createCommand.jksAlias;

                String didLogEntry = null;
                try {

                    Signer signer = null;
                    if (signingKeyPemFile != null && verifyingKeyPemFile != null) {
                        signer = new Signer(signingKeyPemFile, verifyingKeyPemFile);
                    } else if (jksFile != null && jksPassword != null && jksAlias != null) {
                        signer = new Signer(new FileInputStream(jksFile), jksPassword, jksAlias);
                    }

                    if (signer == null) {
                        System.err.println("Source for the (signing/verifying) keys undefined. Use one of the relevant options to supply keys");
                        jc.usage();
                        System.exit(1);
                    }

                    didLogEntry = TdwCreator.builder()
                            .signer(signer)
                            .assertionMethods(assertionMethodsMap)
                            .build()
                            .create(domain, path);

                } catch (Exception e) {
                    System.err.println("Command '" + parsedCmdStr + "' failed due to: " + e.getLocalizedMessage());
                    System.exit(1);
                }

                System.out.println(didLogEntry);

                break;

            default:
                System.err.println("Invalid command: " + parsedCmdStr);
                jc.usage();
                System.exit(1);
        }

        System.exit(0);
    }
}