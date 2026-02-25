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

    static DidLogCreatorStrategy getCreatorStrategy(DidLogCreatorContext ctx) throws DidLogCreatorStrategyException {

        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (!ctx.nextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is currently not supported for %s DID logs", ctx.getDidMethod()));
                }

                return TdwCreator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethods(ctx.assertionMethods())
                        .authentications(ctx.authentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.updateKeysDidMethodParameter())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryCreator.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethods(ctx.assertionMethods())
                        .authentications(ctx.authentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.updateKeysDidMethodParameter())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.nextKeyHashesDidMethodParameter())
                        .build();
            }
        }

        throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
    }

    static DidLogUpdaterStrategy getUpdaterStrategy(DidLogUpdaterContext ctx) throws DidLogUpdaterStrategyException {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (!ctx.nextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is currently not supported for %s DID logs", ctx.getDidMethod()));
                }

                return TdwUpdater.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethods(ctx.assertionMethods())
                        .authentications(ctx.authentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.updateKeysDidMethodParameter())
                        // CAUTION Not implemented yet:
                        // .nextKeys(ctx.getNextKeys())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryUpdater.builder()
                        .cryptographicSuite(ctx.getCryptoSuite())
                        .assertionMethods(ctx.assertionMethods())
                        .authentications(ctx.authentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.updateKeysDidMethodParameter())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.nextKeyHashesDidMethodParameter())
                        .build();
            }
        }

        throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
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
        }

        throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
    }
}
