package com.e2ew.e2e.keys.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.e2ew.e2e.keys.exceptions.AuthCryptoE2eException;
import com.e2ew.e2e.keys.filter.utils.ModifiableRequestWrapper;
import com.e2ew.e2e.keys.model.ClientKeys;
import com.e2ew.e2e.keys.security.ClientKeysSession;
import com.e2ew.e2e.keys.security.JweService;
import com.e2ew.e2e.keys.security.JwsService;
import com.nimbusds.jose.JWEObject;

@Component
public class InE2eCryptoPreprocessingFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(InE2eCryptoPreprocessingFilter.class);
    public static final String PARAMETER_E2E = "_e2e_crypto";
    public static final String SESSION_CLIENT_ID = "sessionClientId";
    public static final String PATH_PUBLIC = "PATH_PUBLIC";
    public static final String PATH_PILOT = "PATH_PILOT";
    public static final String PATH_INFRA = "PATH_INFRA";

    private final ObjectMapper om = new ObjectMapper();
    private final JweService jweService;
    private final JwsService jwsService;
    private final ClientKeysSession clientKeysSession;

    private static final Set<String> BODY_METHODS = Set.of("POST", "PUT", "PATCH", "DELETE");

    public InE2eCryptoPreprocessingFilter(JweService jweService, JwsService jwsService,
            ClientKeysSession clientKeysSession) {
        this.jweService = jweService;
        this.jwsService = jwsService;
        this.clientKeysSession = clientKeysSession;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        var isInfra = (boolean) request.getAttribute(PATH_INFRA);
        if (isInfra) {
            // No procesar E2E Crypto para requests de infraestructura
            filterChain.doFilter(request, response);
            return;
        }
        ModifiableRequestWrapper requestWrapper = new ModifiableRequestWrapper(request);

        String xJws = requestWrapper.getHeader("X-JWS");         // firma detached o JWS compacto
        String contentType = requestWrapper.getContentType();
        String method = requestWrapper.getMethod();

        if (method == null || !BODY_METHODS.contains(method.toUpperCase(Locale.ROOT))) {
            filterChain.doFilter(requestWrapper, response);
            return;
        }
        boolean isJson;
        boolean isJweContent;
        if (contentType == null) {
            isJson = false;
            isJweContent = false;
        } else {
            try {
                MediaType mt = MediaType.parseMediaType(contentType);
                isJson = mt.isCompatibleWith(MediaType.APPLICATION_JSON)
                        || mt.getSubtype().toLowerCase(Locale.ROOT).endsWith("+json");
                isJweContent = mt.isCompatibleWith(MediaType.parseMediaType("application/jwe"));
            } catch (InvalidMediaTypeException ex) {
                throw new AuthCryptoE2eException("Content-Type inválido", HttpStatus.UNSUPPORTED_MEDIA_TYPE);
            }
        }

        if (!isJson && !isJweContent) {
            log.error("Content-Type inválido para procesar E2E Crypto: {}", contentType);
            throw new AuthCryptoE2eException(
                    "Content-Type " + contentType + " inválido. Esperado: application/json o application/jwe",
                    HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        }

        try {

            // solo procesar si el método requiere body
            final byte[] raw = requestWrapper.getBody();
            if (raw.length == 0) {
                throw new AuthCryptoE2eException("No hay body en la request para procesar E2E Crypto", HttpStatus.BAD_REQUEST);
            }
            final String bodyStr = new String(raw, StandardCharsets.UTF_8);

            ClientKeys rqClientKeys = null;
            //obtener clientId de la request (seteado en filtro anterior)
            /*
             * El clientId puede ser PATH_PUBLIC si es un recurso público, es decir, no hay token, por lo que no se valida firma
             * Si no es PATH_PUBLIC, se espera que venga X-JWS para validar firma, ya que el JWT token es obligatorio para cualquier otro recurso
             * y requiere una sesión activa con llaves cargadas en caché.
             * Aparte, puede ser PATH_PILOT para recursos de piloto que no requieren firma.
             */
            Object clientIdAttr = request.getAttribute(SESSION_CLIENT_ID);
            String clientId = (clientIdAttr instanceof String clientIdS) ? clientIdS : null;

            if (clientId == null || clientId.isBlank()) {
                log.error("No se encontró el clientId en la request para procesar E2E Crypto");
                throw new AuthCryptoE2eException("Request no válido para E2E Crypto, origen desconocido",
                        HttpStatus.METHOD_NOT_ALLOWED);
            }
            // ¿Hay que verificar firma?
            boolean mustVerifySignature = !PATH_PUBLIC.equals(clientId) && !PATH_PILOT.equals(clientId);

            if (mustVerifySignature) {
                if (xJws == null || xJws.isBlank()) {
                    log.error("No se encontró el header X-JWS en la request para procesar la firma E2E Crypto");
                    throw new AuthCryptoE2eException(
                            "No se encontró el header X-JWS en la request para procesar la firma E2E Crypto");
                }
                rqClientKeys = clientKeysSession.getClientKeys(clientId)
                        .orElseThrow(() -> new AuthCryptoE2eException(
                                "No se encontraron llaves de firma, no se puede verificar la autenticidad de la petición",
                                HttpStatus.UNAUTHORIZED));
            }

            if (bodyStr.isBlank()) {
                log.debug("No hay body en la request, y se requiere para procesar E2E Crypto");
                throw new AuthCryptoE2eException("No hay body en la request para procesar E2E Crypto",
                        HttpStatus.BAD_REQUEST);
            } else if (isCompactJwe(bodyStr)) {
                //es JWE compacto
                var decryptedJson = this.processSimpleStructureJWE(bodyStr);
                if (mustVerifySignature) {
                    //verificar firma
                    verifySignature(decryptedJson, xJws, rqClientKeys, clientId);
                }
                requestWrapper.setContentType("application/json;charset=UTF-8");
                requestWrapper.setBody(decryptedJson);
                filterChain.doFilter(requestWrapper, response);
                return;

            } else if (isJsonSerializedJwe(bodyStr)) {
                if (mustVerifySignature) {
                    //verificar firma
                    this.verifySignature(raw, xJws, rqClientKeys, clientId);
                }

                byte[] clearBytes = this.getClearBodyWhenHasE2eParameter(raw);

                requestWrapper.setContentType("application/json;charset=UTF-8");
                requestWrapper.setBody(clearBytes);
                filterChain.doFilter(requestWrapper, response);
                return;
            } else if (bodyStr.startsWith("{") && bodyStr.endsWith("}")) {
                //es body normal sin JWE
                if (mustVerifySignature) {
                    //verificar firma
                    verifySignature(raw, xJws, rqClientKeys, clientId);
                }
                filterChain.doFilter(requestWrapper, response);
                return;
            }
            //no es ni JWE compacto ni JSON serializado
            log.debug("El body no es un JWE válido ni un JSON válido");
            throw new AuthCryptoE2eException("El body no es un JWE válido ni un JSON válido", HttpStatus.BAD_REQUEST);
        } catch (AuthCryptoE2eException e2eException) {
            log.error("Error en InE2eCryptoPreprocessingFilter - URI: {}, Método: {}, Error: {}",
                    request.getRequestURI(),
                    request.getMethod(),
                    e2eException.getMessage(),
                    e2eException);
            response.setContentType("application/json");
            response.setStatus(e2eException.getHttpStatus());

            Map<String, Object> errorDetails = new HashMap<>();
            errorDetails.put("timestamp", LocalDateTime.now().toString());
            errorDetails.put("status", e2eException.getHttpStatus());
            errorDetails.put("error", "Error al procesar la solicitud E2E Crypto");
            errorDetails.put("message", e2eException.getMessage());
            errorDetails.put("path", request.getRequestURI());

            try {
                String jsonError = om.writeValueAsString(errorDetails);
                response.getWriter().write(jsonError);
                response.getWriter().flush();
            } catch (IOException e) {
                log.error("Error al escribir la respuesta JSON", e);
            }
        }
    }

    /**
     * Obtiene el body claro cuando el JSON tiene el parámetro _e2e_crypto
     * @param raw body raw
     * @return body claro con campos descifrados
     * @throws AuthCryptoE2eException error del parseo o lectura de la solicitud
     */
    private byte[] getClearBodyWhenHasE2eParameter(byte[] raw) {
        final ObjectNode rqNode;
        try {
            rqNode = (ObjectNode) om.readTree(raw);
        } catch (JacksonException e) {
            throw new AuthCryptoE2eException("No se pudo leer la solicitud correctamente", HttpStatus.CONFLICT);
        }

        // Aceptar tanto string compacto como objeto con campos JWE
        JsonNode encNode = rqNode.get(PARAMETER_E2E);
        if (encNode == null || encNode.isNull()) {
            throw new AuthCryptoE2eException("Sobre JSON sin _e2e_crypto");
        }

        byte[] decryptedJsonBytes;
        if (encNode.isString()) {
            // Compact JWE string
            decryptedJsonBytes = this.processSimpleStructureJWE(encNode.asText());
        } else {
            throw new AuthCryptoE2eException("Formato de _e2e_crypto no soportado");
        }

        if (decryptedJsonBytes.length == 0) {
            throw new AuthCryptoE2eException("El _e2e_crypto no contiene datos descifrables");
        }

        try {
            ObjectNode decryptedNode = (ObjectNode) om.readTree(decryptedJsonBytes);
            decryptedNode.properties()
                    .forEach(e -> rqNode.set(e.getKey(), e.getValue()));
            rqNode.remove(PARAMETER_E2E);

            return om.writeValueAsBytes(rqNode);
        } catch (Exception e) {
            throw new AuthCryptoE2eException("No se pudo reescribir la solicitud con datos descifrados",
                    HttpStatus.CONFLICT, e);
        }
    }

    private void verifySignature(byte[] decryptedJson, String xJws, ClientKeys rqClientKeys, String clientId) {
        var isVerified = jwsService.verifyDetached(decryptedJson, xJws, rqClientKeys.pubKeySignature());
        if (!isVerified) {
            log.debug("La firma JWS detached no pudo ser verificada, firma inválida");
            log.warn("Cerrando sesión del cliente ID {} por firma inválida", clientId);
            clientKeysSession.closeSessionClient(clientId);
            throw new AuthCryptoE2eException(
                    "La firma JWS detached no pudo ser verificada, firma inválida", HttpStatus.UNAUTHORIZED);
        }
    }

    private boolean isCompactJwe(String s) {
        if (s == null || s.isBlank())
            return false;
        try {
            JWEObject.parse(s); // acepta EncryptedKey vacío cuando corresponde
            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    private boolean isJsonSerializedJwe(String s) {
        if (s == null || s.isBlank())
            return false;
        try {
            JsonNode node = om.readTree(s);
            // campos comunes en JWE JSON (flattened o general)
            return (node.has(PARAMETER_E2E) && node.get(PARAMETER_E2E).isTextual());
        } catch (JacksonException ex) {
            return false;
        }
    }

    private byte[] processSimpleStructureJWE(String jweCompact) {
        var decryptedJson = jweService.decryptCompact(jweCompact);
        if (decryptedJson.length == 0) {
            log.debug("El JWE no contiene datos descifrables");
            throw new AuthCryptoE2eException("El JWE no contiene datos descifrables");
        }
        return decryptedJson;
    }

}
