// src/test/java/com/e2ew/e2e/keys/InE2eCryptoPreprocessingFilterMockIT.java
package com.e2ew.e2e.keys;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.e2ew.e2e.E2eApplication;
import com.e2ew.e2e.keys.cache.KeyCacheService;
import com.e2ew.e2e.keys.model.AcceptEncryptionMethod;
import com.e2ew.e2e.keys.model.ClientKeys;
import com.e2ew.e2e.keys.security.ClientKeysSession;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;

@SpringBootTest(classes = {E2eApplication.class,
        InE2eCryptoPreprocessingFilterMockIT.TestBeans.class})
@AutoConfigureMockMvc
class InE2eCryptoPreprocessingFilterMockIT {

    @Autowired MockMvc mvc;

    // ✅ Llaves reales inyectadas como beans (se usan si tu filtro o lógica las necesitara).
    @Autowired OctetKeyPair clientSigPriv;
    @Autowired OctetKeyPair clientSigPub;
    @Autowired OctetKeyPair clientEncPriv;
    @Autowired OctetKeyPair clientEncPub;
    @Autowired OctetKeyPair serverEncPriv;
    @Autowired OctetKeyPair serverEncPub;

    // ✅ Mocks inyectados como beans @Primary (reemplazan los reales si existieran)
//    @Autowired JwsService jwsService;            // es un mock de Mockito
    @Autowired ClientKeysSession clientKeysSession; // mock también

    @Test
    void escenario1_bodyEsJWECompacto_descifra_y_verificaFirma_detached_sobre_claro() throws Exception {
        // Cuerpo en claro
        String clearJson = "{\"nombre\":\"Juan\",\"monto\":1000}";
        byte[] clearBytes = clearJson.getBytes(StandardCharsets.UTF_8);

        // Cliente: JWS DETACHED sobre el cuerpo EN CLARO
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();

        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(clearBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigPriv));
        String xJwsHeaderValue = jwsDetached.serialize(true);

        // Cliente: JWE del MISMO cuerpo en claro
        JWEHeader jweHdr = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.XC20P)
                .keyID(serverEncPub.getKeyID())
                .build();

        JWEObject jwe = new JWEObject(jweHdr, new Payload(clearBytes));
        jwe.encrypt(new X25519Encrypter(serverEncPub));
        String bodyJwe = jwe.serialize();

        // Session: devolver ClientKeys con las públicas
        when(clientKeysSession.getClientKeys("CLIENT-1"))
                .thenReturn(Optional.of(new ClientKeys("CLIENT-1", clientSigPub, clientEncPub)));

        when(clientKeysSession.getClientKeys(anyString()))
                .thenReturn(Optional.of(new ClientKeys("CLIENT-1", clientSigPub, clientEncPub)));
        when(clientKeysSession.getAlgEncPermission(anyString()))
                .thenReturn(AcceptEncryptionMethod.A256GCM);

        mvc.perform(
                        post("/echo")
                                .contentType("application/jwe")
                                .requestAttr("sessionClientId", "CLIENT-1")
                                .requestAttr("PATH_INFRA", false)
                                .header("X-JWS", xJwsHeaderValue)
                                .content(bodyJwe)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(clearJson));
    }

    @Test
    void escenario2_sobreJSON_con__e2e_crypto__verifica_detached_sobre_raw_y_luego_fusiona() throws Exception {
        // Campos sensibles en claro que se cifrarán
        String sensitiveFieldsJson = "{\"numeroIdentidad\":\"123456\",\"cuenta\":\"001-ABC\"}";
        byte[] sensitiveBytes = sensitiveFieldsJson.getBytes(StandardCharsets.UTF_8);

        // Cliente: JWE de los campos sensibles
        JWEHeader jweHdr = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.XC20P)
                .keyID(serverEncPub.getKeyID())
                .build();

        JWEObject jwe = new JWEObject(jweHdr, new Payload(sensitiveBytes));
        jwe.encrypt(new X25519Encrypter(serverEncPub));
        String innerJwe = jwe.serialize();

        // JSON on-wire: campos públicos + _e2e_crypto
        String onWire = """
                {"tipo":"PAGO","_e2e_crypto":"%s"}
                """.formatted(innerJwe).replace("\n", "").trim();
        byte[] onWireBytes = onWire.getBytes(StandardCharsets.UTF_8);

        // Cliente: JWS DETACHED sobre el JSON completo on-wire (con JWE dentro)
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();

        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(onWireBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigPriv));
        String xJwsHeaderValue = jwsDetached.serialize(true);

        // JSON esperado después del merge: campos públicos + campos descifrados
        String expectedMerged = "{\"tipo\":\"PAGO\",\"numeroIdentidad\":\"123456\",\"cuenta\":\"001-ABC\"}";

        when(clientKeysSession.getClientKeys("CLIENT-1"))
                .thenReturn(Optional.of(new ClientKeys("CLIENT-1", clientSigPub, clientEncPub)));

        mvc.perform(
                        post("/echo")
                                .contentType(MediaType.APPLICATION_JSON)
                                .requestAttr("sessionClientId", "CLIENT-1")
                                .header("X-JWS", xJwsHeaderValue)
                                .content(onWire)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(expectedMerged));
    }

    @Test
    void escenario3_jsonClaro_verifica_detached_y_pasa_directo() throws Exception {
        String clearJson = "{\"x\":1,\"y\":2}";
        byte[] clearBytes = clearJson.getBytes(StandardCharsets.UTF_8);

        // Cliente: JWS DETACHED sobre el JSON en claro
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();

        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(clearBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigPriv));
        String xJwsHeaderValue = jwsDetached.serialize(true);

        when(clientKeysSession.getClientKeys("CLIENT-1"))
                .thenReturn(Optional.of(new ClientKeys("CLIENT-1", clientSigPub, clientEncPub)));

        mvc.perform(
                        post("/echo")
                                .contentType(MediaType.APPLICATION_JSON)
                                .requestAttr("sessionClientId", "CLIENT-1")
                                .header("X-JWS", xJwsHeaderValue)
                                .content(clearJson)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(clearJson));
    }

    @Test
    void escenarioErroneo_forzarCatch_y_verRespuestaError() throws Exception {
        // Construir JSON con _e2e_crypto textual (no importa su contenido porque el JweService será mockeado)
        String onWire = "{\"tipo\":\"PAGO\",\"_e2e_crypto\":\"INVALID-JWE-CONTENT\"}";
        byte[] onWireBytes = onWire.getBytes(StandardCharsets.UTF_8);

        // Firma detached válida sobre el JSON on-wire
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();

        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(onWireBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigPriv));
        String xJwsHeaderValue = jwsDetached.serialize(true);

        // Mock: el cliente existe
        when(clientKeysSession.getClientKeys("CLIENT-1"))
                .thenReturn(Optional.of(new ClientKeys("CLIENT-1", clientSigPub, clientEncPub)));

        // Ejecutar petición. El JweService está mockeado para devolver bytes vacíos -> causará excepción dentro del try
        mvc.perform(
                        post("/echo")
                                .contentType(MediaType.APPLICATION_JSON)
                                .requestAttr("sessionClientId", "CLIENT-1")
                                .header("X-JWS", xJwsHeaderValue)
                                .content(onWire)
                )
                .andDo(print())
                .andExpect(status().isConflict())
                .andExpect(content().contentType("application/json"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Error al procesar la solicitud E2E Crypto")));
    }

    @TestConfiguration
    static class TestBeans {

        // --- Beans de llaves (reales) ---
        @Bean
        OctetKeyPair clientSigPriv() throws Exception {
            return new OctetKeyPairGenerator(Curve.Ed25519).keyID("client-sig").generate();
        }

        @Bean
        OctetKeyPair clientSigPub(OctetKeyPair clientSigPriv) {
            return clientSigPriv.toPublicJWK();
        }

        @Bean
        OctetKeyPair clientEncPriv() throws Exception {
            return new OctetKeyPairGenerator(Curve.X25519).keyID("server-enc").generate();
        }

        @Bean
        OctetKeyPair clientEncPub(OctetKeyPair clientEncPriv) {
            return clientEncPriv.toPublicJWK();
        }

        @Bean
        OctetKeyPair serverEncPriv() throws Exception {
            return new OctetKeyPairGenerator(Curve.X25519).keyID("server-enc").generate();
        }

        @Bean
        OctetKeyPair serverEncPub(OctetKeyPair serverEncPriv) {
            return serverEncPriv.toPublicJWK();
        }

        @Bean
        @Primary
        ClientKeysSession clientKeysSessionMock() {
            return Mockito.mock(ClientKeysSession.class);
        }

        @Bean
        @Primary
        KeyCacheService keyCacheServiceMock(OctetKeyPair serverEncPriv) {
            KeyCacheService mock = Mockito.mock(KeyCacheService.class);
            KeyCacheService.KeyRecord keyRecord = new KeyCacheService.KeyRecord(serverEncPriv.getKeyID(), serverEncPriv,
                    "ACTUAL", null);
            when(mock.findForDecryptionStrict(anyString())).thenReturn(keyRecord);
            return mock;
        }

    }
}
