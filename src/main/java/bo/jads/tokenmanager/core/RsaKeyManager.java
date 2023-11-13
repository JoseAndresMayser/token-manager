package bo.jads.tokenmanager.core;

import bo.jads.tokenmanager.exceptions.keys.*;

import java.io.*;
import java.security.*;

class RsaKeyManager {

    private String privateKeyPath;
    private String publicKeyPath;

    public void initialize(String privateKeyPath, String publicKeyPath) {
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
    }

    public Boolean keysExist() {
        File privateKeyFile = new File(privateKeyPath);
        File publicKeyFile = new File(publicKeyPath);
        return privateKeyFile.exists() && publicKeyFile.exists();
    }

    public void generateKeys() throws KeysGenerationException {
        File privateKeyFile = generatePrivateKeyFile();
        File publicKeyFile = generatePublicKeyFile();
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            ObjectOutputStream privateKeyOos = new ObjectOutputStream(new FileOutputStream(privateKeyFile));
            privateKeyOos.writeObject(keyPair.getPrivate());
            privateKeyOos.close();
            ObjectOutputStream publicKeyOos = new ObjectOutputStream(new FileOutputStream(publicKeyFile));
            publicKeyOos.writeObject(keyPair.getPublic());
            publicKeyOos.close();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new KeysGenerationException(e);
        }
    }

    public PrivateKey getPrivateKey() throws PrivateKeyReadException {
        if (privateKeyPath == null || privateKeyPath.isBlank()) {
            throw new PrivateKeyReadException("The private key path must not be null or empty.");
        }
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(privateKeyPath));
            return (PrivateKey) objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new PrivateKeyReadException(e);
        }
    }

    public PublicKey getPublicKey() throws PublicKeyReadException {
        if (publicKeyPath == null || publicKeyPath.isBlank()) {
            throw new PublicKeyReadException("The public key path must not be null or empty.");
        }
        try {
            ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(publicKeyPath));
            return (PublicKey) objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new PublicKeyReadException(e);
        }
    }

    private File generatePrivateKeyFile() throws PrivateKeyGenerationException {
        File privateKeyFile = new File(privateKeyPath);
        File parentFile = privateKeyFile.getParentFile();
        if (parentFile != null) {
            if (!parentFile.mkdirs()) {
                throw new PrivateKeyGenerationException();
            }
        }
        try {
            if (!privateKeyFile.createNewFile()) {
                throw new PrivateKeyGenerationException();
            }
        } catch (IOException e) {
            throw new PrivateKeyGenerationException(e);
        }
        return privateKeyFile;
    }

    private File generatePublicKeyFile() throws PublicKeyGenerationException {
        File publicKeyFile = new File(publicKeyPath);
        File parentFile = publicKeyFile.getParentFile();
        if (parentFile != null) {
            if (!parentFile.mkdirs()) {
                throw new PublicKeyGenerationException();
            }
        }
        try {
            if (!publicKeyFile.createNewFile()) {
                throw new PublicKeyGenerationException();
            }
        } catch (IOException e) {
            throw new PublicKeyGenerationException(e);
        }
        return publicKeyFile;
    }

}
