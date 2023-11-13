package bo.jads.tokenmanager.exceptions;

public class TokenGenerationException extends Exception {

    public TokenGenerationException(String message) {
        super(message);
    }

    public TokenGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

}
