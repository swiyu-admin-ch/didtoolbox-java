package ch.admin.bj.swiyu.didtoolbox;

import java.io.Serial;

/**
 * The class {@code TdwDeactivatorException} is a <em>checked exception</em> class indicating conditions related to
 * {@code TdwDeactivator} class that any reasonable application might want to catch.
 *
 * @see TdwDeactivator
 */
public class TdwDeactivatorException extends Exception {

    @Serial
    private static final long serialVersionUID = 3703612925023452498L;

    public TdwDeactivatorException(String message) {
        super(message);
    }

    public TdwDeactivatorException(Exception e) {
        super(e);
    }

    public TdwDeactivatorException(String message, Throwable cause) {
        super(message, cause);
    }
}