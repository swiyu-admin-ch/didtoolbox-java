package org.examples;

import ch.admin.bj.swiyu.didtoolbox.JwkUtils;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogCreatorStrategyException;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterContext;
import ch.admin.bj.swiyu.didtoolbox.context.DidLogUpdaterStrategyException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;

public class Main {

    public static void main(String... args) {

        // The helper key store having default capacity is 5 (keys)
        RandomEd25519KeyStore.init(10);

        try {
            System.out.println(build());
        } catch (URISyntaxException | IOException | DidLogCreatorStrategyException | DidLogUpdaterStrategyException |
                 InvalidKeySpecException err) {
            System.err.println(err.getMessage());
            System.exit(1);
        }

        System.exit(0);
    }

    static String build() throws URISyntaxException, IOException, DidLogCreatorStrategyException, DidLogUpdaterStrategyException, InvalidKeySpecException {

        // initial DID log entry
        var didLog = new StringBuilder(
                // initial (by default, did:webvh:1.0) DID log entry (featuring a pre-rotation key)
                DidLogCreatorContext.builder()
                        .cryptographicSuite(RandomEd25519KeyStore.asCryptographicSuite())
                        // IMPORTANT Calling this method activates key pre-rotation
                        .nextKeyHashesDidMethodParameter(Set.of(
                                // get a whole another pre-rotation key to be used when building the next DID log entry.
                                // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                RandomEd25519KeyStore.rotate().asNextKeyHashesDidMethodParameter()
                                // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                //          MUST entirely match the "updateKeys" values in the DID log next entry
                                //,RandomEd25519KeyStore.rotate().getNextKeyHashesDidMethodParameter(),
                                //,RandomEd25519KeyStore.rotate().getNextKeyHashesDidMethodParameter()
                        ))
                        // Forced to avoid error: "The PEM file(s) exist(s) already and will remain intact until overwrite mode is engaged: .didtoolbox/auth-key-01"
                        .forceOverwrite(true)
                        .build()
                        .create(URL.of(new URI("https://identifier-reg.trust-infra.swiyu-int.admin.ch/api/v1/did/18fa7c77-9dd1-4e20-a147-fb1bec146085"), null))
        ).append(System.lineSeparator());

        // Update the DID log by adding as many entries as there are keys in the store.
        // Keep "rotating" (pre-rotation) keys while updating
        var i = 0;
        while (i++ < RandomEd25519KeyStore.getCapacity()) {

            didLog.append(
                    // next DID log entry
                    DidLogUpdaterContext.builder()
                            // switch to the key defined by the "nextKeyHashes" from the previous entry (the key store is already "rotated" earlier)
                            .cryptographicSuite(RandomEd25519KeyStore.asCryptographicSuite())
                            // REMINDER .didtoolbox directory was created previously while building the initial DID log entry (thanks to .forceOverwrite(true))
                            .assertionMethodKeys(Map.of("my-assert-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of(".didtoolbox/assert-key-01.pub"), "my-assert-key-0" + i))).authenticationKeys(Map.of("my-auth-key-0" + i, JwkUtils.loadECPublicJWKasJSON(Path.of(".didtoolbox/auth-key-01.pub"), "my-auth-key-0" + i)))
                            // Prepare ("rotate" to) another pre-rotation key to be used when building the next DID log entry
                            .nextKeyHashesDidMethodParameter(Set.of(
                                    // Bear in mind, after the key store "rotation", all its (static) helpers "point" to the next/another key in the store
                                    RandomEd25519KeyStore.rotate().asNextKeyHashesDidMethodParameter()
                                    // REMINDER Indeed, you may keep adding more keys this way - beware that some of them
                                    //          MUST entirely match the "updateKeys" values in the DID log next entry
                                    //,RandomEd25519KeyStore.rotate().getNextKeyHashesDidMethodParameter(),
                                    //,RandomEd25519KeyStore.rotate().getNextKeyHashesDidMethodParameter()
                            ))
                            .build()
                            .update(didLog.toString())
            ).append(System.lineSeparator());
        }

        return didLog.toString();
    }
}