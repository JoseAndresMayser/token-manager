package bo.jads.tokenmanager.core;

import bo.jads.tokenmanager.dto.TokenRequest;
import bo.jads.tokenmanager.dto.TokenResponse;
import bo.jads.tokenmanager.exceptions.TokenDataException;
import bo.jads.tokenmanager.exceptions.TokenGenerationException;
import bo.jads.tokenmanager.exceptions.TokenValidationException;
import bo.jads.tokenmanager.exceptions.keys.KeysException;
import bo.jads.tokenmanager.exceptions.keys.PrivateKeyReadException;
import bo.jads.tokenmanager.exceptions.keys.PublicKeyReadException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.shaded.gson.Gson;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.UUID;

public class TokenManager {

    private final RsaKeyManager rsaKeyManager;
    private static TokenManager tokenManager;
    private static final String DATA = "data";

    private TokenManager() {
        rsaKeyManager = new RsaKeyManager();
    }

    public static TokenManager getInstance() {
        if (tokenManager == null) {
            tokenManager = new TokenManager();
        }
        return tokenManager;
    }

    public void initialize(String privateKeyPath, String publicKeyPath, Boolean generateKeysIfNotExist)
            throws KeysException {
        rsaKeyManager.initialize(privateKeyPath, publicKeyPath);
        if (rsaKeyManager.keysExist()) {
            return;
        }
        if (!generateKeysIfNotExist) {
            throw new KeysException("Could not find keys.");
        }
        rsaKeyManager.generateKeys();
    }

    public TokenResponse generateToken(TokenRequest<?> request) throws TokenGenerationException {
        Calendar calendar = Calendar.getInstance();
        calendar.add(request.getExpirationTimeType().getValue(), request.getExpirationTimeAmount());
        Date expirationTime = calendar.getTime();
        Date currentDate = new Date();
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(request.getSubject())
                .issuer("web")
                .expirationTime(expirationTime)
                .notBeforeTime(currentDate)
                .issueTime(currentDate)
                .jwtID(UUID.randomUUID().toString())
                .claim(DATA, new Gson().toJson(request.getData()))
                .build();
        try {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyManager.getPrivateKey();
            JWSSigner jwsSigner = new RSASSASigner(rsaPrivateKey);
            JWSObject jwsObject =
                    new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload(jwtClaimsSet.toJSONObject()));
            jwsObject.sign(jwsSigner);
            return new TokenResponse(jwsObject.serialize(), expirationTime);
        } catch (PrivateKeyReadException e) {
            throw new TokenGenerationException("Could not read private key to generate token.", e);
        } catch (JOSEException e) {
            throw new TokenGenerationException("Could not sign token.", e);
        }
    }

    public Boolean tokenIsValid(String token) throws TokenValidationException {
        return !tokenExpired(token) && tokenIntegrityIsValid(token);
    }

    public Boolean tokenExpired(String token) throws TokenValidationException {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getExpirationTime().before(new Date());
        } catch (ParseException e) {
            throw new TokenValidationException("Could not parse token.", e);
        }
    }

    public Boolean tokenIntegrityIsValid(String token) throws TokenValidationException {
        try {
            return SignedJWT.parse(token).verify(new RSASSAVerifier((RSAPublicKey) rsaKeyManager.getPublicKey()));
        } catch (ParseException e) {
            throw new TokenValidationException("Could not parse token.", e);
        } catch (PublicKeyReadException e) {
            throw new TokenValidationException("Could not read public key to validate token integrity.", e);
        } catch (JOSEException e) {
            throw new TokenValidationException("Failed to verify signature to validate token.", e);
        }
    }

    public <Data> Data getDataFromToken(String token, Class<Data> dataClass) throws TokenDataException {
        try {
            return new Gson().fromJson(SignedJWT.parse(token).getJWTClaimsSet().getClaim(DATA).toString(), dataClass);
        } catch (ParseException e) {
            throw new TokenDataException("Could not parse token.", e);
        }
    }

}
