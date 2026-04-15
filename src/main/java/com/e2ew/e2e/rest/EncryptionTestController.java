package com.e2ew.e2e.rest;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Map;
import java.util.Set;

import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.e2ew.e2e.keys.cache.KeyCacheService;
import com.e2ew.e2e.keys.security.annotations.EncryptField;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
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

@RestController

@Profile("dev")
@RequestMapping("/.internal/enc-test")
public class EncryptionTestController {

    private final KeyCacheService keyCacheService;

    public EncryptionTestController(KeyCacheService keyCacheService) {
        this.keyCacheService = keyCacheService;
    }

    @GetMapping("/client-keys")
    public ResponseEntity<Object> getClientKeys() throws JOSEException {

        var singKey = new OctetKeyPairGenerator(Curve.Ed25519).keyID("client-sig").generate();
        var encKey = new OctetKeyPairGenerator(Curve.X25519).keyID("client-enc").generate();

        Map<String, Object> clientKeys = Map.of(
                "signingKey", singKey.toJSONObject(),
                "encryptionKey", encKey.toJSONObject()
        );

        return ResponseEntity.ok(clientKeys);
    }

    public record EchoResponseEntity(String body, @EncryptField String anotherField) {
    }
    @PostMapping(value = "/echo", consumes = {MediaType.APPLICATION_JSON_VALUE,
            "application/jwe"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<EchoResponseEntity> echo(@RequestBody String body) {
        return ResponseEntity.ok(new EchoResponseEntity(body,
                "texto encriptado")); // devolvemos EXACTO lo que llega al controller (post-filtro)
    }

    @PostMapping("/enc-all-body")
    public ResponseEntity<Object> encryptAllBody(@RequestBody EncAllBodyDTO data) throws ParseException, JOSEException {

        OctetKeyPair clientSigPriv = OctetKeyPair.parse(data.privSignKey());
        var clientSigPub = clientSigPriv.toPublicJWK();

        byte[] clearBytes = data.allBody().getBytes(StandardCharsets.UTF_8);

        // Cliente: JWS DETACHED sobre el cuerpo EN CLARO
        JWSHeader detachedHdr = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                .keyID(clientSigPub.getKeyID())
                .base64URLEncodePayload(false)
                .criticalParams(Set.of("b64"))
                .build();

        JWSObject jwsDetached = new JWSObject(detachedHdr, new Payload(clearBytes));
        jwsDetached.sign(new Ed25519Signer(clientSigPriv));
        String xJwsHeaderValue = jwsDetached.serialize(true);

        var kidEndSer = keyCacheService.getActivePublicKey().getKeyID();
        // Cliente: JWE del MISMO cuerpo en claro
        JWEHeader jweHdr = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.XC20P)
                .keyID(kidEndSer)
                .build();

        JWEObject jwe = new JWEObject(jweHdr, new Payload(clearBytes));
        jwe.encrypt(new X25519Encrypter(keyCacheService.getActivePublicKey()));
        String bodyJwe = jwe.serialize();

        Map<String, String> body = Map.of(
                "jwe", bodyJwe,
                "jwsHeader", xJwsHeaderValue
        );

        return ResponseEntity.ok(body);
    }

    public record EncAllBodyDTO(String allBody, String privSignKey) {
    }

}
