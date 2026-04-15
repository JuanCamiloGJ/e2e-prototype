package com.e2ew.e2e.keys.utils;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;

public final class JwkUtils {
    private static final Logger log = LoggerFactory.getLogger(JwkUtils.class);

    private JwkUtils() {}

    /**
     * Valida un JWK OKP público o una clave pública en Base64/Base64URL.
     * @param input         Clave pública en JWK JSON, Base64URL o Base64.
     * @param expectedCrv   Curva esperada ("Ed25519" o "X25519").
     * @return              La representación JWK JSON si es válida.
     * Lanza IllegalArgumentException si no es válido.
     * Nota: si la entrada es un JWK JSON, el campo 'kid' será requerido para permitir la identificación
     *       posterior de la clave por el cliente/servicio.
     */
    public static String validateOkpPublicKey(String input, String expectedCrv) {
        if (input == null || input.trim().isEmpty()) {
            log.error("Clave pública OKP vacía");
            throw new IllegalArgumentException("Clave vacía");
        }
        String trimmed = input.trim();
        // Si la cadena viene entre comillas (p. ej. '"{...}"'), quitar comillas externas
        if (trimmed.length() >= 2 && trimmed.charAt(0) == '"' && trimmed.charAt(trimmed.length() - 1) == '"') {
            trimmed = trimmed.substring(1, trimmed.length() - 1).trim();
        }
        // Si parece JSON, intentar parsear como JWK
        if (trimmed.startsWith("{") || trimmed.contains("\"kty\"") || trimmed.contains("\"crv\"")) {
            validateJwkJson(trimmed, expectedCrv);
            return trimmed; // devolver la versión "limpia" (sin espacios/quotes externas)
        }
        // Si no es JSON, tratar como Base64URL o Base64
        byte[] decoded = decodeBase64OrBase64Url(trimmed);
        if (decoded == null) {
            log.error("Clave pública OKP no es Base64/ Base64URL válido");
            throw new IllegalArgumentException("No es Base64/ Base64URL válido");
        }
        // No se puede verificar 'crv' cuando solo viene raw bytes; asumimos que el llamador verifica contexto (Ed25519/X25519).
        // Caso 2: puede ser un JWK JSON codificado en Base64; intentar interpretar como JSON
        String decodedStr = new String(decoded, StandardCharsets.UTF_8).trim();
        if (decodedStr.length() >= 2 && decodedStr.charAt(0) == '"'
                && decodedStr.charAt(decodedStr.length() - 1) == '"') {
            decodedStr = decodedStr.substring(1, decodedStr.length() - 1).trim();
        }
        if (decodedStr.startsWith("{") || decodedStr.contains("\"kty\"") || decodedStr.contains("\"crv\"")) {
            validateJwkJson(decodedStr, expectedCrv);
            return decodedStr;
        }
        log.error("Clave pública OKP tiene longitud inválida: {} bytes (esperados 32), y no es JWK JSON", decoded.length);
        throw new IllegalArgumentException("Longitud de clave inválida: " + decoded.length + " bytes (esperados 32), y no es JWK JSON");
    }

    public static boolean isValidOkpPublicKey(String input, String expectedCrv) {
        try {
            validateOkpPublicKey(input, expectedCrv);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static void validateJwkJson(String jwkJson, String expectedCrv) {
        try {
            JWK jwk = JWK.parse(jwkJson);
            if (!(jwk instanceof OctetKeyPair okp)) {
                log.error("JWK no es OKP");
                throw new IllegalArgumentException("JWK no es OKP");
            }

            if (okp.getKeyType() != KeyType.OKP) {
                log.error("kty inválido en JWK: {}", okp.getKeyType());
                throw new IllegalArgumentException("kty inválido");
            }
            String crv = okp.getCurve().getName();
            if (!expectedCrv.equalsIgnoreCase(crv)) {
                log.error("crv inválido en JWK: {} (esperado: {})", crv, expectedCrv);
                throw new IllegalArgumentException("crv inválido (esperado: " + expectedCrv + ")");
            }
            if (okp.getD() != null) {
                log.error("JWK contiene parámetro privado 'd'");
                throw new IllegalArgumentException("No enviar parámetros privados (d)");
            }
            if (okp.getX() == null) {
                log.error("Falta campo 'x' en JWK");
                throw new IllegalArgumentException("Falta campo 'x' en JWK");
            }
            byte[] xb = okp.getX().decode();
            if (xb.length != 32) {
                log.error("Longitud inválida de 'x' en JWK: {}", xb.length);
                throw new IllegalArgumentException("Longitud de 'x' inválida: " + xb.length);
            }
            // Requisito adicional: 'kid' es necesario para identificar la clave en pasos posteriores
            String kid = okp.getKeyID();
            if (kid == null || kid.trim().isEmpty()) {
                log.error("Falta campo 'kid' en JWK");
                throw new IllegalArgumentException("Falta campo 'kid' en JWK");
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException("JWK inválido: parse error", e);
        }
    }

    private static byte[] decodeBase64OrBase64Url(String s) {
        // intentar Base64URL (acepta '-' y '_' sin padding)
        try {
            return new Base64URL(s).decode();
        } catch (IllegalArgumentException ignored) {
            // intentar Base64 estándar
        }
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException ignored) {
            return null; // intención: null indica que no se pudo decodificar
        }
    }
}
