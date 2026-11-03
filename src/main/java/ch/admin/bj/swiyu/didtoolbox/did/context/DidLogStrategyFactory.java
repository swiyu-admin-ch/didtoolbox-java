package ch.admin.bj.swiyu.didtoolbox.did.context;

import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwDeactivator;
import ch.admin.bj.swiyu.didtoolbox.did.tdw.TdwUpdater;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryCreator;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryDeactivator;
import ch.admin.bj.swiyu.didtoolbox.did.webvh.WebVerifiableHistoryUpdater;

/**
 * The factory delivering all possible strategies in regard to DID log manipulation, regardless of DID method.
 */
final class DidLogStrategyFactory {

    private DidLogStrategyFactory() {
    }

    static DidLogCreatorStrategy getCreatorStrategy(DidLogCreatorContext ctx) throws DidLogCreatorStrategyException {

        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {
                throw new IllegalArgumentException(String.format("TDWs are no longer supported.", ctx.getDidMethod()));
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryCreator.builder(ctx.getCryptographicSuite())
                        .assertionMethods(ctx.getAssertionMethods())
                        .authentications(ctx.getAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .nextKeyHashesDidMethodParameter(ctx.getNextKeyHashesDidMethodParameter())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }

    static DidLogUpdaterStrategy getUpdaterStrategy(DidLogUpdaterContext ctx) throws DidLogUpdaterStrategyException {
        switch (ctx.getDidMethod()) {
            case TDW_0_3 -> {

                if (!ctx.getNextKeyHashesDidMethodParameter().isEmpty()) {
                    throw new IllegalArgumentException(String.format("The key pre-rotation is currently not supported for %s DID logs", ctx.getDidMethod()));
                }

                return TdwUpdater.builder(ctx.getCryptographicSuite())
                        .assertionMethods(ctx.getAssertionMethods())
                        .authentications(ctx.getAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
                        // CAUTION Not implemented yet:
                        // .nextKeys(ctx.getNextKeys())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryUpdater.builder(ctx.getCryptographicSuite())
                        .assertionMethods(ctx.getAssertionMethods())
                        .authentications(ctx.getAuthentications())
                        // Using alternative and more potent method to supply the parameter.
                        // Eventually, all supplied keys are combined and their distinct values are taken.
                        .updateKeysDidMethodParameter(ctx.getUpdateKeysDidMethodParameter())
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
                return TdwDeactivator.builder(ctx.getCryptographicSuite())
                        .build();
            }
            case WEBVH_1_0 -> {
                return WebVerifiableHistoryDeactivator.builder(ctx.getCryptographicSuite())
                        .build();
            }
            default -> throw new IllegalArgumentException("The supplied DID log features an unsupported DID method");
        }
    }
}
