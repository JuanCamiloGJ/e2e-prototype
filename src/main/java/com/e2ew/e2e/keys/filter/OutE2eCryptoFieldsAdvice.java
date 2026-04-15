package com.e2ew.e2e.keys.filter;

import java.util.Collection;

import jakarta.servlet.http.HttpServletRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import com.e2ew.e2e.keys.exceptions.AuthCryptoE2eException;
import com.e2ew.e2e.keys.model.AcceptEncryptionMethod;
import com.e2ew.e2e.keys.model.ClientKeys;
import com.e2ew.e2e.keys.security.ClientKeysSession;
import com.e2ew.e2e.keys.security.annotations.EncryptObject;
import com.e2ew.e2e.keys.utils.AccessPlans;
import com.e2ew.e2e.keys.utils.ConstantsE2e;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.X25519Encrypter;
import com.nimbusds.jose.jwk.OctetKeyPair;

@RestControllerAdvice
public class OutE2eCryptoFieldsAdvice implements ResponseBodyAdvice<Object> {

    private static final Logger log = LoggerFactory.getLogger(OutE2eCryptoFieldsAdvice.class);
    // Si algún día quieres cambiar el nombre del campo del envelope:
    private static final String ENVELOPE_FIELD_NAME = "responseBody";
    private final ObjectMapper mapper = new ObjectMapper();
    private final ClientKeysSession sessionKeys;

    public OutE2eCryptoFieldsAdvice(ClientKeysSession sessionKeys) {
        this.sessionKeys = sessionKeys;
    }

    @Override
    public boolean supports(MethodParameter returnType,
            Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request,
            ServerHttpResponse response) {
        if (body == null) {
            return null;
        }
        HttpServletRequest httpRequest = extractHttpRequest(request);
        if (httpRequest == null) {
            log.debug("No HTTP servlet request available, skipping E2E encryption");
            return body;
        }
        // 2. Validación combinada de rutas excluidas
        if (isExcludedPath(httpRequest)) {
            return body;
        }
        // 3. Extraer body real una sola vez
        Object realBody = unwrapResponseEntity(body);
        if (realBody == null || !isEncryptable(realBody)) {
            return body;
        }
        String clientId = (String) httpRequest.getAttribute(ConstantsE2e.SESSION_CLIENT_ID);

        EncryptionContext ctx = buildEncryptionContext(clientId);

        AccessPlans.AccessPlan plan = AccessPlans.planFor(realBody);
        // Determinar el objeto real a procesar
        Object targetDto = plan.innerObject();

        // 6. Decisión de cifrado sin validaciones duplicadas
        if (targetDto.getClass().isAnnotationPresent(EncryptObject.class)) {
            return encryptFull(targetDto, realBody, plan.isEnvelope(), ctx);
        }
        // No hay campos marcados para cifrado selectivo
        if (plan.encryptFieldNames().isEmpty()) {
            return body;
        }

        return encryptFields(targetDto, realBody, plan, ctx);

    }

    /**
     * Cifra solo los campos marcados en el DTO
     * @param targetDto Objeto DTO a cifrar parcialmente
     * @param realBody Objeto real de respuesta (para envelope)
     * @param plan Plan de acceso con campos a cifrar
     * @param ctx Contexto de cifrado
     * @return Objeto con campos cifrados o envelope con objeto cifrado
     */
    private Object encryptFields(Object targetDto, Object realBody, AccessPlans.AccessPlan plan,
            EncryptionContext ctx) {
        JsonNode processed = processFieldsDto(targetDto, plan, ctx.enc(), ctx.clientKeys());

        if (!plan.isEnvelope())
            return processed;
        ObjectNode envelopeNode = mapper.valueToTree(realBody);
        envelopeNode.set(ENVELOPE_FIELD_NAME, processed);
        return envelopeNode;
    }

    /**
     * Cifra el objeto DTO completo en un único JWE
     * Si hay envelope, lo mete en el campo correspondiente, si no, devuelve el string cifrado
     * @param targetDto Objeto a cifrar completo
     * @param realBody Objeto real de respuesta (para envelope)
     * @param hasEnvelope Indica si hay envelope
     * @param ctx Contexto de cifrado
     * @return Objeto cifrado o envelope con objeto cifrado
     */
    private Object encryptFull(Object targetDto, Object realBody, boolean hasEnvelope, EncryptionContext ctx) {
        String encrypted = processAllDto(targetDto, ctx.enc(), ctx.clientKeys());

        if (!hasEnvelope)
            return encrypted;

        ObjectNode envelopeNode = mapper.valueToTree(realBody);
        envelopeNode.put(ENVELOPE_FIELD_NAME, encrypted);
        return envelopeNode;
    }

    private HttpServletRequest extractHttpRequest(ServerHttpRequest request) {
        return (request instanceof ServletServerHttpRequest servletRequest)
                ? servletRequest.getServletRequest()
                : null;
    }

    private boolean isExcludedPath(HttpServletRequest httpRequest) {
        Boolean isInfra = (Boolean) httpRequest.getAttribute(ConstantsE2e.PATH_INFRA);
        if (Boolean.TRUE.equals(isInfra))
            return true;

        String clientId = (String) httpRequest.getAttribute(ConstantsE2e.SESSION_CLIENT_ID);
        return ConstantsE2e.PATH_PILOT.equalsIgnoreCase(clientId)
                || ConstantsE2e.PATH_PUBLIC.equalsIgnoreCase(clientId);
    }

    private Object unwrapResponseEntity(Object body) {
        return (body instanceof ResponseEntity<?> re) ? re.getBody() : body;
    }

    private boolean isEncryptable(Object obj) {
        return !(obj instanceof String
                || obj.getClass().isPrimitive()
                || obj instanceof Number
                || obj instanceof Boolean
                || obj instanceof Collection
                || obj.getClass().isArray());
    }

    private EncryptionContext buildEncryptionContext(String clientId) {
        ClientKeys clientKeys = sessionKeys.getClientKeys(clientId)
                .orElseThrow(() -> new AuthCryptoE2eException(
                        "No hay llaves del cliente en sesión", HttpStatus.UNPROCESSABLE_ENTITY));

        AcceptEncryptionMethod acceptEnc = sessionKeys.getAlgEncPermission(clientId);
        EncryptionMethod enc = AcceptEncryptionMethod.A256GCM.equals(acceptEnc)
                ? EncryptionMethod.A256GCM
                : EncryptionMethod.XC20P;

        return new EncryptionContext(clientKeys, enc);
    }

    private String processAllDto(Object dto, EncryptionMethod enc, ClientKeys clientKeys) {
        ObjectNode bodyNode = mapper.valueToTree(dto);
        // Cifrado del bloque sensible en un único JWE
        final byte[] plaintext;
        try {
            plaintext = mapper.writeValueAsBytes(bodyNode);
        } catch (Exception e) {
            throw new AuthCryptoE2eException("Error serializando bloque sensible", HttpStatus.UNPROCESSABLE_ENTITY, e);
        }
        var userEncKey = clientKeys.pubKeyEncryption();
        JWEHeader jweHdr = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                .keyID(userEncKey.getKeyID())
                .build();
        try {
            JWEObject jwe = new JWEObject(jweHdr, new Payload(plaintext));
            jwe.encrypt(new X25519Encrypter(userEncKey));
            return jwe.serialize();
        } catch (Exception e) {
            throw new AuthCryptoE2eException("Error cifrando bloque sensible", HttpStatus.UNPROCESSABLE_ENTITY, e);
        }
    }

    /**
     * Toma un DTO cualquiera, extrae @EncryptField, agrupa, cifra y pone _e2e_crypto.
     */
    private JsonNode processFieldsDto(Object dto, AccessPlans.AccessPlan plan,
            EncryptionMethod enc, ClientKeys clientKeys) {
        ObjectNode bodyNode = mapper.valueToTree(dto);

        if (plan.encryptFieldNames().isEmpty())
            return bodyNode;

        // Evitar crear ObjectNode vacío innecesariamente
        ObjectNode sensitive = extractSensitiveFields(bodyNode, plan.encryptFieldNames());
        if (sensitive.isEmpty())
            return bodyNode;

        String encryptedBlock = encryptBlock(sensitive, enc, clientKeys);
        bodyNode.put(ConstantsE2e.PARAMETER_E2E, encryptedBlock);

        return bodyNode;
    }

    private ObjectNode extractSensitiveFields(ObjectNode source, Collection<String> fieldNames) {
        ObjectNode sensitive = mapper.createObjectNode();
        for (String name : fieldNames) {
            JsonNode value = source.remove(name); // remove retorna el valor
            if (value != null && !value.isNull()) {
                sensitive.set(name, value);
            }
        }
        return sensitive;
    }

    private String encryptBlock(JsonNode data, EncryptionMethod enc, ClientKeys clientKeys) {
        try {
            byte[] plaintext = mapper.writeValueAsBytes(data);
            OctetKeyPair userEncKey = clientKeys.pubKeyEncryption();

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, enc)
                    .keyID(userEncKey.getKeyID())
                    .build();

            JWEObject jwe = new JWEObject(header, new Payload(plaintext));
            jwe.encrypt(new X25519Encrypter(userEncKey));

            return jwe.serialize();
        } catch (Exception e) {
            throw new AuthCryptoE2eException("Error cifrando bloque sensible",
                    HttpStatus.UNPROCESSABLE_CONTENT, e);
        }
    }

    private record EncryptionContext(ClientKeys clientKeys, EncryptionMethod enc) {
    }

}
