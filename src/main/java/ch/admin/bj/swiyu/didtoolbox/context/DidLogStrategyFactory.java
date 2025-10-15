package ch.admin.bj.swiyu.didtoolbox.context;

import ch.admin.bj.swiyu.didtoolbox.TdwCreator;
import ch.admin.bj.swiyu.didtoolbox.TdwDeactivator;
import ch.admin.bj.swiyu.didtoolbox.TdwUpdater;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryCreator;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryDeactivator;
import ch.admin.bj.swiyu.didtoolbox.webvh.WebVerifiableHistoryUpdater;

/**
 * The factory delivering all possible strategies in regard to DID log manipulation, regardless of DID method.
 */
@SuppressWarnings({"PMD.LawOfDemeter"})
final class DidLogStrategyFactory {

    private DidLogStrategyFactory() {
    }

    static DidLogCreatorStrategy getCreatorStrategy(DidLogCreatorContext ctx) {

        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                return TdwCreator.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        .updateKeys(ctx.getUpdateKeys())
                        .forceOverwrite(ctx.isForceOverwrite())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryCreator.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        .updateKeys(ctx.getUpdateKeys())
                        .nextKeys(ctx.getNextKeyHashes())
                        .forceOverwrite(ctx.isForceOverwrite())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogUpdaterStrategy getUpdaterStrategy(DidLogUpdaterContext ctx) {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                return TdwUpdater.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        .updateKeys(ctx.getUpdateKeys())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryUpdater.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        .updateKeys(ctx.getUpdateKeys())
                        // TODO .nextKeys(ctx.getNextKeyHashes())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogDeactivatorStrategy getDeactivatorStrategy(DidLogDeactivatorContext ctx) {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                return TdwDeactivator.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryDeactivator.builder()
                        .verificationMethodKeyProvider(ctx.getVerificationMethodKeyProvider())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }
}
