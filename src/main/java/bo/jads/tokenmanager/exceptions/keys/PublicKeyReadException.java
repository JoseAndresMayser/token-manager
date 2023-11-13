package bo.jads.tokenmanager.exceptions.keys;

public class PublicKeyReadException extends KeysException {

    public PublicKeyReadException(String message) {
        super(message);
    }

    public PublicKeyReadException(Throwable cause) {
        super("Cannot get public key.", cause);
    }

}
