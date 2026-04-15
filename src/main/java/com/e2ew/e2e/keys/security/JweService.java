package com.e2ew.e2e.keys.security;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.e2ew.e2e.keys.cache.KeyCacheService;
import com.e2ew.e2e.keys.exceptions.AuthCryptoE2eException;
import com.e2ew.e2e.keys.exceptions.KidNotFoundException;
import com.e2ew.e2e.keys.rotate.KeyRotationBroadcaster;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.OctetKeyPair;

/**
 * Se encarga de descifrar/cifrar JWE usando llaves del KeyCacheService.
 */
@Component
public class JweService {

    // Algoritmos soportados (ajústalos a tu contrato)
    private static final JWEAlgorithm EXPECTED_ALG = JWEAlgorithm.ECDH_ES;         // o ECDH_ES_A256KW
    private static final EncryptionMethod EXPECTED_ENC = EncryptionMethod.A256GCM; // o AcceptEncryptionMethod.XC20P
    private final KeyCacheService keyCache;
    private final KeyRotationBroadcaster keyRotationBroadcaster;
    private static final Set<EncryptionMethod> ACCEPTED_ENC = Set.of(
            EncryptionMethod.A256GCM,
            EncryptionMethod.XC20P
    );

    public JweService(KeyCacheService keyCache, KeyRotationBroadcaster keyRotationBroadcaster) {
        this.keyCache = keyCache;
        this.keyRotationBroadcaster = keyRotationBroadcaster;
    }

    /**
     * Descifra un JWE compacto y devuelve el payload (bytes).
     */
    public byte[] decryptCompact(String compactJWE) {
        final JWEObject jwe;
        final String kid;

        try {
            jwe = JWEObject.parse(compactJWE);
            kid = getKid(jwe);
        } catch (ParseException | JOSEException e) {
            throw new AuthCryptoE2eException("JWE inválido", HttpStatus.CONFLICT, e);
        }

        try {
            return tryDecrypt(jwe, kid);
        } catch (KidNotFoundException knf) {
            // refresh bloqueante (pero deduplicado y con cooldown)
            keyRotationBroadcaster.refreshNow("xxxx");
            // reintento único
            try {
                return tryDecrypt(jwe, kid);
            } catch (KidNotFoundException knf2) {
                throw new AuthCryptoE2eException("No existe kid=" + kid, HttpStatus.UNAUTHORIZED, knf2);
            } catch (JOSEException e) {
                throw new AuthCryptoE2eException("Error descifrando JWE", HttpStatus.CONFLICT, e);
            }
        } catch (JOSEException e) {
            throw new AuthCryptoE2eException("Error descifrando JWE", HttpStatus.CONFLICT, e);
        }
    }

    private byte[] tryDecrypt(JWEObject jwe, String kid) throws JOSEException {
        var kr = keyCache.findForDecryptionStrict(kid);
        JWEDecrypter decrypter = new X25519Decrypter(kr.okp());
        jwe.decrypt(decrypter);
        return jwe.getPayload().toBytes();
    }

    private String getKid(JWEObject jwe) throws JOSEException {
        JWEHeader h = jwe.getHeader();

        // Validaciones defensivas
        if (!EXPECTED_ALG.equals(h.getAlgorithm())) {
            throw new JOSEException("alg inesperado: " + h.getAlgorithm());
        }
        if (!ACCEPTED_ENC.contains(h.getEncryptionMethod())) {
            throw new JOSEException("enc no permitido: " + h.getEncryptionMethod());
        }
        String kid = h.getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new JOSEException("kid ausente en el header JWE");
        }
        return kid;
    }

    /**
     * (Opcional) Cifra un payload para tu propia pública ACTIVA (respuesta o prueba).
     */
    public String encryptForActivePublic(byte[] plaintext) {
        try {
            OctetKeyPair pubActive = keyCache.getActivePublicKey();

            // Header con 'kid' activo para que el receptor (tú) sepa qué privada usar
            JWEHeader header = new JWEHeader.Builder(EXPECTED_ALG, EXPECTED_ENC)
                    .keyID(pubActive.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            JWEEncrypter encrypter = new X25519Encrypter(pubActive);
            jwe.encrypt(encrypter);

            return jwe.serialize();
        } catch (JOSEException e) {
            throw new AuthCryptoE2eException("Error cifrando JWE", HttpStatus.CONFLICT, e);
        }
    }

    /**
     * (Opcional) Cifra un payload con la llave publica del cliente .
     */
    public String encryptForActivePublicClient(byte[] plaintext, String jsonClientEncKeyPub) {
        try {
            var clientEncKeyPub = OctetKeyPair.parse(jsonClientEncKeyPub); // valida que es OKP
            // Header con 'kid' activo para que el receptor (tú) sepa qué privada usar
            JWEHeader header = new JWEHeader.Builder(EXPECTED_ALG, EXPECTED_ENC)
                    .keyID(clientEncKeyPub.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            JWEEncrypter encrypter = new X25519Encrypter(clientEncKeyPub);
            jwe.encrypt(encrypter);

            return jwe.serialize();
        } catch (JOSEException e) {
            throw new AuthCryptoE2eException("Error cifrando JWE", HttpStatus.CONFLICT, e);
        } catch (ParseException e) {
            throw new AuthCryptoE2eException("Error parseando JWK pública del cliente", HttpStatus.BAD_REQUEST, e);
        }
    }

    /**
     * (Opcional) Cifra un payload con la llave publica del cliente y método de cifrado especificado.
     * @param plaintext bytes a cifrar
     * @param jsonClientEncKeyPub JWK pública de encriptación del cliente en formato JSON
     * @param encMethod método de cifrado a usar
     * @return El JWE compacto cifrado.
     */
    public String encryptForActivePublicClient(byte[] plaintext, String jsonClientEncKeyPub, EncryptionMethod encMethod) {
        try {
            var clientEncKeyPub = OctetKeyPair.parse(jsonClientEncKeyPub); // valida que es OKP
            // Header con 'kid' activo para que el receptor (tú) sepa qué privada usar
            JWEHeader header = new JWEHeader.Builder(EXPECTED_ALG, encMethod)
                    .keyID(clientEncKeyPub.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            JWEEncrypter encrypter = new X25519Encrypter(clientEncKeyPub);
            jwe.encrypt(encrypter);

            return jwe.serialize();
        } catch (JOSEException e) {
            throw new AuthCryptoE2eException("Error cifrando JWE", HttpStatus.CONFLICT, e);
        } catch (ParseException e) {
            throw new AuthCryptoE2eException("Error parseando JWK pública del cliente", HttpStatus.BAD_REQUEST, e);
        }
    }

    /**
     * Helper si prefieres trabajar con String UTF-8.
     * @return El JWE compacto cifrado.
     */
    public String encryptForActivePublic(String plaintext) {
        return encryptForActivePublic(plaintext.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Helper si prefieres trabajar con String UTF-8.
     * @return El payload descifrado como String.
     */
    public String decryptToString(String compactJWE) {
        return new String(decryptCompact(compactJWE), StandardCharsets.UTF_8);
    }
}
