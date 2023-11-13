package bo.jads.tokenmanager.exceptions.keys;

public class PrivateKeyGenerationException extends KeysGenerationException {

    public PrivateKeyGenerationException() {
        super("Could not generate private key.");
    }

    public PrivateKeyGenerationException(Throwable cause) {
        super("Could not generate private key.", cause);
    }

}
