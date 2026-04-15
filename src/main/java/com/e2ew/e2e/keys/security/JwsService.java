package com.e2ew.e2e.keys.security;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import com.e2ew.e2e.keys.exceptions.AuthCryptoE2eException;
import com.e2ew.e2e.keys.model.ClientKeys;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;

@Component
public class JwsService {

    private static final Logger log = LoggerFactory.getLogger(JwsService.class);

    public boolean verifySignature(JWSObject jwsParsed, ClientKeys clientKeys) {
        try {
            var isVerified = jwsParsed.verify(new Ed25519Verifier(clientKeys.pubKeySignature()));
            log.trace("JWS signature verified: {}", isVerified);
            return isVerified;
        } catch (JOSEException e) {
            log.error("Error verifying JWS signature: {}", e.getMessage());
            return false;
        }

    }

    /** Verifica JWS DETACHED (b64=false). Debes pasar los bytes EXACTOS del payload tal como viajaron. */
    public boolean verifyDetached(byte[] payloadRaw, String compactJws, OctetKeyPair clientSigPublic) {
        Objects.requireNonNull(payloadRaw, "payloadRaw");
        Objects.requireNonNull(compactJws, "compactJws");
        Objects.requireNonNull(clientSigPublic, "clientSigPublic");

        try {
            // Re-adjunta el payload crudo al parsear (requisito Nimbus p/ detached)
            JWSObject jws = JWSObject.parse(compactJws, new Payload(payloadRaw));

            // Checks de header mínimos
            JWSHeader h = jws.getHeader();
            if (!JWSAlgorithm.EdDSA.equals(h.getAlgorithm())) {
                log.error("JWS alg no soportado: {}", h.getAlgorithm());
                throw new AuthCryptoE2eException("JWS alg no soportado: " + h.getAlgorithm());
            }
            if (h.isBase64URLEncodePayload() || !h.getCriticalParams().contains("b64")) {
                log.error("JWS no es detached (b64=true/crit)");
                throw new AuthCryptoE2eException("JWS no es detached (b64=true/crit)");
            }

            return jws.verify(new Ed25519Verifier(clientSigPublic));
        } catch (Exception e) {
            throw new AuthCryptoE2eException("Error verifying JWS detached", HttpStatus.CONFLICT, e);
        }
    }


}
