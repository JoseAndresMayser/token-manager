package bo.jads.tokenmanager.core;

import bo.jads.tokenmanager.dto.TokenRequest;
import bo.jads.tokenmanager.dto.TokenResponse;
import bo.jads.tokenmanager.exceptions.TokenDataException;
import bo.jads.tokenmanager.exceptions.TokenGenerationException;
import bo.jads.tokenmanager.exceptions.TokenValidationException;
import bo.jads.tokenmanager.exceptions.keys.KeysException;
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

    private TokenManager() {
        rsaKeyManager = new RsaKeyManager();
    }

    public static TokenManager getInstance() {
        if (tokenManager == null) {
            tokenManager = new TokenManager();
        }
        return tokenManager;
    }

    public TokenResponse generateToken(TokenRequest<?> request) throws TokenGenerationException {
        rsaKeyManager.initialize(request.getPrivateKeyPath(), request.getPublicKeyPath());
        try {
            if (!rsaKeyManager.keysExist()) {
                if (!request.getGenerateKeysIfNotExist()) {
                    throw new TokenGenerationException("Could not find keys to generate token.");
                }
                rsaKeyManager.generateKeys();
            }
            Calendar calendar = Calendar.getInstance();
            calendar.add(request.getExpirationTimeType().getValue(), request.getExpirationTimeAmount());
            Date expirationTime = calendar.getTime();
            Date currentDate = new Date();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(request.getSubject())
                    .issuer("web")
                    .expirationTime(expirationTime)
                    .notBeforeTime(currentDate)
                    .issueTime(currentDate)
                    .jwtID(UUID.randomUUID().toString())
                    .claim(DATA_KEY, new Gson().toJson(request.getData()))
                    .build();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) rsaKeyManager.getPrivateKey();
            JWSSigner jwsSigner = new RSASSASigner(rsaPrivateKey);
            JWSObject jwsObject =
                    new JWSObject(new JWSHeader(JWSAlgorithm.RS256), new Payload(claimsSet.toJSONObject()));
            jwsObject.sign(jwsSigner);
            return new TokenResponse(jwsObject.serialize(), expirationTime);
        } catch (KeysException e) {
            throw new TokenGenerationException("Failed to generate keys to generate token.", e);
        } catch (JOSEException e) {
            throw new TokenGenerationException("Could not sign token.", e);
        }
    }

    public Boolean tokenIsValid(String token) throws TokenValidationException {
        try {
            SignedJWT signedJwt = parseTokenToSignedJwt(token);
            JWTClaimsSet jwtClaimsSet = signedJwt.getJWTClaimsSet();
            Date expirationTime = jwtClaimsSet.getExpirationTime();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyManager.getPublicKey();
            JWSVerifier jwsVerifier = new RSASSAVerifier(rsaPublicKey);
            return !expirationTime.before(new Date()) && signedJwt.verify(jwsVerifier);
        } catch (ParseException e) {
            throw new TokenValidationException("Could not parse token.", e);
        } catch (PublicKeyReadException e) {
            throw new TokenValidationException("Could not read public key to validate token.", e);
        } catch (JOSEException e) {
            throw new TokenValidationException("Failed to verify signature to validate token.", e);
        }
    }

    public <Data> Data getDataFromToken(String token, Class<Data> dataClass) throws TokenDataException {
        try {
            SignedJWT signedJwt = parseTokenToSignedJwt(token);
            JWTClaimsSet jwtClaimsSet = signedJwt.getJWTClaimsSet();
            String dataString = jwtClaimsSet.getClaim(DATA_KEY).toString();
            return new Gson().fromJson(dataString, dataClass);
        } catch (ParseException e) {
            throw new TokenDataException("Could not parse token.", e);
        }
    }

    private SignedJWT parseTokenToSignedJwt(String token) throws ParseException {
        return SignedJWT.parse(token);
    }

    private static final String DATA_KEY = "data";

}
