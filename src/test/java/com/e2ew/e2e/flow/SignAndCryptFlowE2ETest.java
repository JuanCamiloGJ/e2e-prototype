package com.e2ew.e2e.flow;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.X25519Decrypter;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

class SignAndCryptFlowE2ETest {

    // Util: bytes UTF-8
    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test
    void signClearBody_detachedHeader_and_encryptSameBody_jwe_then_decrypt_and_verify() throws Exception {
        // ====== Claves de prueba ======
        // Firma del cliente (Ed25519)
        OctetKeyPair clientSigKp = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("client-sig-" + UUID.randomUUID())
                .generate();
        OctetKeyPair clientSigPub = clientSigKp.toPublicJWK();

        // Cifrado del servidor (X25519)
        OctetKeyPair serverEncKp = new OctetKeyPairGenerator(Curve.X25519)
                .keyID("server-enc-" + UUID.randomUUID())
                .generate();
        OctetKeyPair serverEncPub = serverEncKp.toPublicJWK();

        // ====== Cuerpo en claro (JSON) que se firma y se cifra ======
        String clearJson = """
          {"nombre":"Juan","apellido":"Pérez","cuenta":"123-456"}
        """.trim();
        byte[] clearBytes = utf8(clearJson);

        // ====== Cliente: JWS DETACHED sobre el cuerpo EN CLARO ======
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)   // b64=false (RFC 7797)
                .criticalParams(Set.of("b64"))   // crit=["b64"]
                .build();

        // El payload del JWS son los bytes del clear body (detached)
        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(clearBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigKp));

        // Serialización "detached": <b64(header)>.. <b64(signature)>
        String xJwsHeaderValue = jwsDetached.serialize(true);

        // ====== Cliente: JWE del MISMO cuerpo en claro ======
        JWEHeader jweHdr = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
                .keyID(serverEncPub.getKeyID())
                .build();

        JWEObject jwe = new JWEObject(jweHdr, new Payload(clearBytes));
        jwe.encrypt(new X25519Encrypter(serverEncPub));
        String httpBodyJwe = jwe.serialize(); // Body HTTP que llega al servidor

        // ====== Servidor: flujo estándar => DESCIFRAR -> VERIFICAR ======

        // 1) Descifrar JWE con la privada X25519
        JWEObject jweParsed = JWEObject.parse(httpBodyJwe);
        assertEquals(JWEAlgorithm.ECDH_ES, jweParsed.getHeader().getAlgorithm());
        jweParsed.decrypt(new X25519Decrypter(serverEncKp));
        byte[] recoveredClear = jweParsed.getPayload().toBytes();

        // 2) Verificar firma DETACHED contra esos bytes en claro
        JWSObject jwsParsed = JWSObject.parse(xJwsHeaderValue, new Payload(recoveredClear));

        assertEquals(JWSAlgorithm.EdDSA, jwsParsed.getHeader().getAlgorithm());
        assertFalse(jwsParsed.getHeader().isBase64URLEncodePayload());
        assertTrue(jwsParsed.getHeader().getCriticalParams().contains("b64"));

        boolean ok = jwsParsed.verify(new Ed25519Verifier(clientSigPub));
        assertTrue(ok, "La firma detached debe validar contra el cuerpo en claro recuperado del JWE");

        // 3) Confirmar que lo descifrado coincide exactamente con lo firmado
        assertArrayEquals(clearBytes, recoveredClear, "El claro descifrado debe ser idéntico al firmado");
    }

    @Test
    void tamper_after_decrypt_should_fail_detached_verification() throws Exception {
        // Claves
        OctetKeyPair clientSigKp = new OctetKeyPairGenerator(Curve.Ed25519).keyID("client-sig").generate();
        OctetKeyPair clientSigPub = clientSigKp.toPublicJWK();
        OctetKeyPair serverEncKp = new OctetKeyPairGenerator(Curve.X25519).keyID("server-enc").generate();
        OctetKeyPair serverEncPub = serverEncKp.toPublicJWK();

        // Claro original
        String clearJson = "{\"valor\":1000,\"moneda\":\"COP\"}";
        byte[] clearBytes = utf8(clearJson);

        // JWS detached del claro
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();
        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(clearBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigKp));
        String xJws = jwsDetached.serialize(true);

        // JWE del claro
        JWEObject jwe = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.XC20P).keyID(serverEncPub.getKeyID()).build(),
                new Payload(clearBytes)
        );
        jwe.encrypt(new X25519Encrypter(serverEncPub));
        String bodyJwe = jwe.serialize();

        // Servidor: descifrar
        JWEObject parsed = JWEObject.parse(bodyJwe);
        parsed.decrypt(new X25519Decrypter(serverEncKp));
        byte[] recovered = parsed.getPayload().toBytes();

        // "Manipulación" del claro recuperado antes de validar firma
        String tampered = new String(recovered, StandardCharsets.UTF_8).replace("1000", "1001");
        byte[] tamperedBytes = utf8(tampered);
        JWSObject jwsParsed = JWSObject.parse(xJws, new Payload(tamperedBytes));
        // Verificación debe FALLAR
        boolean ok = jwsParsed.verify(new Ed25519Verifier(clientSigPub));
        assertFalse(ok, "Si el claro cambió, la firma detached debe fallar");
    }
}
