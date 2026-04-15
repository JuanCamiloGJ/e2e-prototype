package com.e2ew.e2e.flow;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.e2ew.e2e.keys.cache.KeyCacheService;
import com.e2ew.e2e.keys.rotate.KeyRotationBroadcaster;
import com.e2ew.e2e.keys.security.JweService;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

// Ajusta los imports de tu KeyCacheService y JweService a tu paquete real

class CryptoFlowE2ETest {

    private final ObjectMapper om = new ObjectMapper();

    private KeyCacheService keyCache;   // tu servicio (versión A, estricta)
    private JweService jweService;      // el servicio de cifrado/descifrado
    private KeyRotationBroadcaster keyRotationBroadcaster;

    // JSON de llaves del servidor (el tuyo real, aquí copiado literal)
    private static final String SERVER_ENVELOPE_JSON = """
                    {
                        "service": "global",
                        "version": 10,
                        "kidActive": "8f7d8c3e-cd09-41a4-9ae9-6cdee891b354",
                        "keys": [
                            {
                                "kid": "8f7d8c3e-cd09-41a4-9ae9-6cdee891b354",
                                "kty": "OKP",
                                "crv": "X25519",
                                "use": "enc",
                                "state": "ACTIVE",
                                "notAfter": "2025-10-25T14:37:05.341048Z",
                                "publicJwk": {
                                    "kty": "OKP",
                                    "crv": "X25519",
                                    "kid": "8f7d8c3e-cd09-41a4-9ae9-6cdee891b354",
                                    "x": "hnl0fs-qK2V0UddcHX8quRUeFEOu6Va-ChE8q3vWBzw"
                                },
                                "privateJwk": {
                                    "kty": "OKP",
                                    "d": "b8IqxxSG4LGaj06bcfVWw0qVhQU18WqddcDmZMmk7qo",
                                    "crv": "X25519",
                                    "kid": "8f7d8c3e-cd09-41a4-9ae9-6cdee891b354",
                                    "x": "hnl0fs-qK2V0UddcHX8quRUeFEOu6Va-ChE8q3vWBzw"
                                }
                            },
                            {
                                "kid": "8b7be235-8bec-4202-b5fa-055321a2fe0b",
                                "kty": "OKP",
                                "crv": "X25519",
                                "use": "enc",
                                "state": "PREVIOUS",
                                "notAfter": "2025-10-24T16:47:52.686813Z",
                                "publicJwk": {
                                    "kty": "OKP",
                                    "crv": "X25519",
                                    "kid": "8b7be235-8bec-4202-b5fa-055321a2fe0b",
                                    "x": "UvfQZ5o1PZqjxLXT2-2OhJfEI394p9_GglpvEX1w-n8"
                                },
                                "privateJwk": {
                                    "kty": "OKP",
                                    "d": "b-I_gV7x2rVFAcYUQm6I45PyOLbBuTe4UMgQyq3VE5I",
                                    "crv": "X25519",
                                    "kid": "8b7be235-8bec-4202-b5fa-055321a2fe0b",
                                    "x": "UvfQZ5o1PZqjxLXT2-2OhJfEI394p9_GglpvEX1w-n8"
                                }
                            }
                        ]
                    }
            """;

    @BeforeEach
    void setup() throws Exception {
        // 1) Cargar llaves del servidor en el KeyCacheService
        keyCache = new KeyCacheService.Factory().keyCacheService();
        Map<String,Object> envelope = om.readValue(SERVER_ENVELOPE_JSON, new TypeReference<>() {});
        keyCache.loadEnvelope(envelope);

        jweService = new JweService(keyCache, keyRotationBroadcaster);
    }

    @ParameterizedTest
    @ValueSource(strings = {"A256GCM", "XC20P"})
    void clientToServer_and_serverToClient_roundtrip(String encName) throws Exception {
        EncryptionMethod enc = "XC20P".equals(encName) ? EncryptionMethod.XC20P : EncryptionMethod.A256GCM;

        // ====== Simular CLIENTE → SERVIDOR ======
        // Cliente toma pública ACTIVA del servidor
        OctetKeyPair serverPublic = keyCache.getActivePublicKey();

        // Cliente cifra payload con alg=ECDH-ES, enc variable, kid=del servidor
        String clientPayload = """
            {"nombre":"Juan","apellido":"Pérez","edad":31}
        """;
        String jweFromClient = encryptWithServerPublic(clientPayload.getBytes(StandardCharsets.UTF_8),
                serverPublic, enc);

        // Servidor recibe y descifra con su privada (buscada por kid)
        String decryptedAtServer = jweService.decryptToString(jweFromClient);
        assertEquals(clientPayload.replaceAll("\\s+",""), decryptedAtServer.replaceAll("\\s+",""));

        // ====== Simular SERVIDOR → CLIENTE ======
        // Simulamos un cliente con su par persistente
        OctetKeyPair clientKeyPair = new OctetKeyPairGenerator(Curve.X25519)
                .keyID("client-" + UUID.randomUUID())
                .generate();
        OctetKeyPair clientPublic = clientKeyPair.toPublicJWK();

        String serverPayload = """
            {"token":"abc123","rol":"USER","exp":"2025-12-31T23:59:59Z"}
        """;

        // Servidor cifra usando pública del cliente (lo habitual tras login)
        String jweFromServer = encryptForClientPublic(serverPayload.getBytes(StandardCharsets.UTF_8),
                clientPublic, enc);

        // Cliente descifra con su privada persistente
        String decryptedAtClient = decryptWithClientPrivate(jweFromServer, clientKeyPair);
        assertEquals(serverPayload.replaceAll("\\s+",""), decryptedAtClient.replaceAll("\\s+",""));
    }

    // ===== Helpers para el test (lado "cliente" y "servidor" simulados en Java) =====

    private String encryptWithServerPublic(byte[] plaintext, OctetKeyPair serverPublic, EncryptionMethod enc) throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                .keyID(serverPublic.getKeyID()) // para que el server seleccione la privada correcta
                .build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        jwe.encrypt(new X25519Encrypter(serverPublic)); // genera epk efímera del "cliente"
        return jwe.serialize();
    }

    private String encryptForClientPublic(byte[] plaintext, OctetKeyPair clientPublic, EncryptionMethod enc) throws Exception {
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                .keyID(clientPublic.getKeyID()) // opcional, útil si cliente maneja varios kid
                .build();
        JWEObject jwe = new JWEObject(header, new Payload(plaintext));
        jwe.encrypt(new X25519Encrypter(clientPublic)); // genera epk efímera del "servidor"
        return jwe.serialize();
    }

    private String decryptWithClientPrivate(String compactJWE, OctetKeyPair clientPrivate) throws Exception {
        JWEObject jwe = JWEObject.parse(compactJWE);
        // El "cliente" valida alg/enc según su lista blanca si quiere
        assertEquals(JWEAlgorithm.ECDH_ES, jwe.getHeader().getAlgorithm());
        assertTrue(jwe.getHeader().getEncryptionMethod().equals(EncryptionMethod.A256GCM)
                || jwe.getHeader().getEncryptionMethod().equals(EncryptionMethod.XC20P));

        jwe.decrypt(new X25519Decrypter(clientPrivate));
        return jwe.getPayload().toString();
    }
}
