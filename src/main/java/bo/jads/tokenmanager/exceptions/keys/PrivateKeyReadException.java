package bo.jads.tokenmanager.exceptions.keys;

public class PrivateKeyReadException extends KeysException {

    public PrivateKeyReadException(String message) {
        super(message);
    }

    public PrivateKeyReadException(Throwable cause) {
        super("Cannot get private key.", cause);
    }

}
