package bo.jads.tokenmanager.exceptions.keys;

public class KeysGenerationException extends KeysException {

    public KeysGenerationException(String message) {
        super(message);
    }

    public KeysGenerationException(Throwable cause) {
        this("Could not generate keys.", cause);
    }

    public KeysGenerationException(String message, Throwable cause) {
        super(message, cause);
    }

}
