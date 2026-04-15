package com.e2ew.e2e.keys.cache;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import tools.jackson.databind.ObjectMapper;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.e2ew.e2e.keys.exceptions.KidNotFoundException;
import com.nimbusds.jose.jwk.OctetKeyPair;

public final class KeyCacheService {
    /** Estado inmutable: consistente entre keys y activeKid. */
    public record CacheState(Map<String, KeyRecord> keys, String activeKid) {}
    // A) Estado único atómico: nunca hay ventana donde activeKid y keys estén desalineados
    private final AtomicReference<CacheState> stateRef =
            new AtomicReference<>(new CacheState(Map.of(), null));
    private final ObjectMapper om = new ObjectMapper();

    KeyCacheService(GuardToken _unused) {
    }

    /**
     * Carga el sobre { kidActive, keys:[...] } y reemplaza todo el caché de forma atómica.
     */
    @SuppressWarnings("unchecked")
    public void loadEnvelope(Map<String, Object> envelope) {
        String newActive = (String) envelope.get("kidActive");
        List<Map<String, Object>> keys = (List<Map<String, Object>>) envelope.get("keys");

        if (newActive == null) {
            throw new IllegalArgumentException("Envelope inválido: kidActive es null");
        }
        if (keys == null || keys.isEmpty()) {
            throw new IllegalArgumentException("Envelope inválido: keys vacío");
        }

        Map<String, KeyRecord> tmp = new HashMap<>(keys.size());

        for (Map<String, Object> k : keys) {
            String kid = (String) k.get("kid");
            String state = (String) k.get("state");
            String notAfterStr = (String) k.get("notAfter");
            Instant notAfter = null;

            if (notAfterStr != null && !notAfterStr.isBlank()) {
                try { notAfter = Instant.parse(notAfterStr); }
                catch (Exception ignored) { /* null */ }
            }

            Map<String, Object> privateJwk = (Map<String, Object>) k.get("privateJwk");
            Map<String, Object> publicJwk = (Map<String, Object>) k.get("publicJwk");

            if (kid == null) {
                throw new IllegalArgumentException("Envelope inválido: kid null");
            }

            try {
                Object jwkObj = (privateJwk != null) ? privateJwk : publicJwk;
                if (jwkObj == null) {
                    throw new IllegalArgumentException("Envelope inválido: no hay publicJwk/privateJwk para kid=" + kid);
                }
                String jwkJson = om.valueToTree(jwkObj).toString();
                OctetKeyPair okp = OctetKeyPair.parse(jwkJson);
                tmp.put(kid, new KeyRecord(kid, okp, state, notAfter));
            } catch (Exception e) {
                throw new RuntimeException("Error parsing JWK for kid " + kid, e);
            }
        }
        // Validación: kidActive debe existir en el set
        if (!tmp.containsKey(newActive)) {
            throw new IllegalStateException("Envelope inválido: kidActive=" + newActive + " no existe en keys");
        }

        stateRef.set(new CacheState(Map.copyOf(tmp), newActive));
    }

    /**
     * Devuelve la clave EXACTA (privada) para descifrar; si no existe, lanza error.
     */
    public KeyRecord findForDecryptionStrict(String kid) {
        KeyRecord r = stateRef.get().keys().get(kid);
        if (r == null)
            throw new KidNotFoundException("No existe clave para kid=" + kid);
        if (!r.canDecrypt())
            throw new IllegalStateException("La clave de kid=" + kid + " no es privada");
        return r;
    }

    /**
     * Devuelve solo la JWK pública del kid activo (para que los clientes cifren hacia ti).
     */
    public OctetKeyPair getActivePublicKey() {
        CacheState s = stateRef.get();
        String k = s.activeKid();
        if (k == null)
            throw new KidNotFoundException("No hay clave activa configurada");
        KeyRecord r = s.keys().get(k);
        if (r == null)
            throw new IllegalStateException("kidActive apunta a una clave inexistente: " + k);
        return r.okp().toPublicJWK();
    }

    /**
     * Conveniencia: para logs/telemetría.
     */
    public String getActiveKid() {
        return stateRef.get().activeKid();
    }

    /**
     * Registro por kid. okp es privada si trae 'd', pública si no.
     */
    public record KeyRecord(String kid, OctetKeyPair okp, String state, Instant notAfter) {
        public boolean canDecrypt() {
            return okp.isPrivate();
        } // tiene 'd'
    }

    private static final class GuardToken {
        private GuardToken() {
        }
    }

    @Configuration
    public static class Factory {
        @Bean
        public KeyCacheService keyCacheService() {
            return new KeyCacheService(new GuardToken());
        }
    }
}


