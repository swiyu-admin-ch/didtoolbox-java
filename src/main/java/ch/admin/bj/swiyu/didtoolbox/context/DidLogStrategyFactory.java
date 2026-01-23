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
final class DidLogStrategyFactory {

    private DidLogStrategyFactory() {
    }

    static DidLogCreatorStrategy getCreatorStrategy(DidLogCreatorContext ctx) {

        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (ctx.getNextKeyHashesDidMethodParameter() != null && !ctx.getNextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is not (yet) implemented for %s DID logs", ctx.getDidMethod()));
                }

                return TdwCreator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .updateKeys(ctx.getUpdateKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        .forceOverwrite(ctx.isForceOverwrite())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryCreator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .updateKeys(ctx.getUpdateKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .nextKeys(ctx.getNextKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.getNextKeyHashesDidMethodParameter())
                        .forceOverwrite(ctx.isForceOverwrite())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogUpdaterStrategy getUpdaterStrategy(DidLogUpdaterContext ctx) {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (ctx.getNextKeyHashesDidMethodParameter() != null && !ctx.getNextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is not (yet) implemented for %s DID logs", ctx.getDidMethod()));
                }

                return TdwUpdater.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .updateKeys(ctx.getUpdateKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        // CAUTION Not implemented yet:
                        // .nextKeys(ctx.getNextKeys())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryUpdater.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethodKeys(ctx.getAssertionMethodKeys())
                        .authenticationKeys(ctx.getAuthenticationKeys())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .updateKeys(ctx.getUpdateKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        // CAUTION Despite its deprecation, it still has to be used here
                        .nextUpdateKeys(ctx.getNextKeys())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.getNextKeyHashesDidMethodParameter())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogDeactivatorStrategy getDeactivatorStrategy(DidLogDeactivatorContext ctx) {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                return TdwDeactivator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryDeactivator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }
}
