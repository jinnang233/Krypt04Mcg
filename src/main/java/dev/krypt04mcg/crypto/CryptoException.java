package dev.krypt04mcg.crypto;

public class CryptoException extends Exception {
    /**
     * Creates a crypto exception with the supplied dependencies and initial state.
     *
     * @param message the message supplied to this operation
     */
    public CryptoException(String message) {
        super(message);
    }

    /**
     * Creates a crypto exception with the supplied dependencies and initial state.
     *
     * @param message the message supplied to this operation
     * @param cause the underlying failure retained as the exception cause
     */
    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
