package ch.admin.eid.did.tdw;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class AssertionMethodInput {

    //private String assertionKey;
    private String assertionPublicKey;

}
