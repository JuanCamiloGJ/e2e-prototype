# Started-E2E
**Librería de seguridad End-to-End (E2E) para aplicaciones Spring Boot**
## Descripción
`started-e2e` es una librería Java que implementa cifrado y firma criptográfica end-to-end utilizando los estándares JWE (JSON Web Encryption) y JWS (JSON Web Signature). Proporciona protección de datos sensibles en tránsito mediante algoritmos modernos basados en curvas elípticas (X25519 y Ed25519).
## Finalidad
- **Cifrado E2E**: Proteger datos sensibles entre cliente y servidor mediante JWE
- **Firma digital**: Garantizar integridad y autenticidad de mensajes mediante JWS
- **Rotación de claves**: Sistema automático de rotación y gestión de claves criptográficas
- **Encriptación selectiva**: Encriptar campos específicos mediante anotaciones y sobres `_e2e_crypto`
- **Integración transparente**: Filtros automáticos para procesar requests/responses
- **Flexibilidad cliente**: El cliente decide cifrar todo el request o solo campos específicos
## Tecnologías
| Componente | Tecnología |
|-----------|-----------|
| Framework | Spring Boot 3.4.10 |
| Lenguaje | Java 17 |
| Criptografía | Nimbus JOSE+JWT 10.5 |
| Cifrado adicional | Google Tink 1.19.0 |
| Service Discovery | Spring Cloud Consul |
## Algoritmos Criptográficos
### Cifrado (JWE)
- **Algoritmo**: `ECDH-ES` (Elliptic Curve Diffie-Hellman Ephemeral Static)
- **Curva**: `X25519`
- **Métodos de cifrado**:
  - `A256GCM` (AES-256-GCM)
  - `XC20P` (XChaCha20-Poly1305)
### Firma (JWS)
- **Algoritmo**: `EdDSA` (Edwards-curve Digital Signature Algorithm)
- **Curva**: `Ed25519`
## Componentes Principales
```
com.e2ew.e2e
├── config/                          # Configuración Spring
├── keys/
│   ├── cache/                       # Gestión de cache de claves
│   │   └── KeyCacheService         # Servicio de cache de claves
│   ├── filter/                      # Filtros HTTP
│   │   ├── InE2eCryptoPreprocessingFilter   # Descifrado de requests
│   │   └── OutE2eCryptoFieldsAdvice         # Cifrado de responses
│   ├── rotate/                      # Rotación de claves
│   │   └── KeyRotationBroadcaster   # Notificación de rotación
│   ├── security/                    # Servicios criptográficos
│   │   ├── JweService              # Cifrado/descifrado JWE
│   │   ├── JwsService              # Firma/verificación JWS
│   │   ├── ClientKeysSession       # Gestión de claves por sesión
│   │   └── annotations/
│   │       ├── @EncryptField       # Marca campos para cifrar
│   │       └── @EncryptObject      # Marca objetos para cifrar
│   └── model/                       # Modelos de datos
└── rest/                            # Controladores REST
    ├── KeysController              # Endpoint de claves públicas
    ├── EncryptionTestController    # Endpoints de prueba
    └── KeyRotationLaunchController # Control de rotación
```
## Flujo de Funcionamiento
### 1. Obtención de Claves Públicas
```http
GET /enc/key
```
**Response:**
```json
{
  "activeKey": {
    "kty": "OKP",
    "crv": "X25519",
    "kid": "8f7d8c3e-cd09-41a4-9ae9-6cdee891b354",
    "x": "hnl0fs-qK2V0UddcHX8quRUeFEOu6Va-ChE8q3vWBzw"
  }
}
```
### 2. Cliente → Servidor (Request Cifrado)
**El cliente decide** si cifra todo el request o solo campos específicos. Ambas opciones son soportadas.
#### Opción A: Cifrado Total del Body
```http
POST /api/endpoint
Content-Type: application/jwe
X-JWS: eyJhbGciOiJFZERTQSIsImtpZCI6ImNsaWVudC1zaWciLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..signature
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6IjhmN2Q4YzNlLWNkMDktNDFhNC05YWU5LTZjZGVlODkxYjM1NCJ9...
```
**Proceso:**
1. Cliente cifra el body completo con la clave pública del servidor (JWE)
2. Cliente firma el body original con su clave privada (JWS detached)
3. Servidor descifra el contenido completo y verifica firma
4. Filtro `InE2eCryptoPreprocessingFilter` procesa automáticamente
#### Opción B: Cifrado Selectivo con Sobre `_e2e_crypto`
```http
POST /api/endpoint
Content-Type: application/json
{
  "userId": "12345",
  "name": "Juan Pérez",
  "_e2e_crypto": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6IjhmN2Q4YzNlIn0..."
}
```
**Estructura del sobre `_e2e_crypto`:**
- Contiene un **único JWE** que encapsula todos los campos sensibles como JSON
- El valor de `_e2e_crypto` es un JWE que al descifrarse produce: `{"email":"juan@example.com","phone":"+58-412-1234567"}`
- Campos no sensibles permanecen fuera del sobre (sin cifrar)
- **El cliente decide** qué campos incluir en el sobre según sus necesidades
**Ejemplo de body original antes de cifrar:**
```json
{
  "userId": "12345",
  "name": "Juan Pérez",
  "email": "juan@example.com",
  "phone": "+58-412-1234567"
}
```
**Proceso:**
1. Cliente identifica campos sensibles (`email`, `phone`)
2. Agrupa los campos sensibles en un objeto JSON: `{"email":"juan@example.com","phone":"+58-412-1234567"}`
3. Cifra el JSON completo con la clave pública del servidor → genera un único JWE
4. Asigna el JWE al campo `_e2e_crypto`
5. Envía request con campos públicos y el sobre `_e2e_crypto`
6. Servidor descifra el JWE del sobre y extrae los campos sensibles
7. Reconstruye el objeto completo fusionando campos públicos y descifrados
### 3. Servidor → Cliente (Response Cifrado)
El servidor usa el sobre `_e2e_crypto` para empaquetar campos marcados con `@EncryptField`.
**Campos marcados con `@EncryptField`:**
```java
public record UserResponse(
    String id,
    String name,
    @EncryptField String email,
    @EncryptField String phone
) {}
```
**Response con estructura estándar:**
```json
{
  "id": "12345",
  "name": "Juan Pérez",
  "_e2e_crypto": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6ImNsaWVudC1lbmMifQ..."
}
```
**Estructura estandarizada del response:**
- **Campos públicos**: en el nivel raíz del JSON
- **Campos sensibles cifrados**: dentro del sobre `_e2e_crypto` como un único JWE
- El JWE contiene un JSON serializado: `{"email":"sensitive@email.com","phone":"555-1234"}`
- El sobre usa el `kid` de la clave pública del cliente
**Proceso:**
1. Controlador retorna objeto con campos anotados `@EncryptField`
2. `OutE2eCryptoFieldsAdvice` detecta las anotaciones
3. Extrae campos marcados y los agrupa en un objeto JSON
4. Cifra el objeto JSON completo con la clave pública del cliente → genera un único JWE
5. Asigna el JWE al campo `_e2e_crypto` en el response
6. Cliente recibe response, descifra el JWE y extrae los campos sensibles
## Ejemplos de Uso
### Cifrado con Anotaciones (Servidor)
```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    @GetMapping("/{id}")
    public UserDTO getUser(@PathVariable String id) {
        return new UserDTO(
            "user-123",
            "Juan Pérez",
            "sensitive@email.com",
            "555-1234",
            "public-info"
        );
    }
    public record UserDTO(
        String id,
        String name,
        @EncryptField String email,
        @EncryptField String phone,
        String publicData
    ) {}
}
```
**Response generado automáticamente:**
```json
{
  "id": "user-123",
  "name": "Juan Pérez",
  "publicData": "public-info",
  "_e2e_crypto": "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6ImNsaWVudC1lbmMifQ..."
}
```

### Cifrado de Response Completo (Servidor)

Usa `@EncryptBody` para cifrar todo el objeto de respuesta, sin estructura de sobre `_e2e_crypto`.

```java
@RestController
@RequestMapping("/api/payments")
public class PaymentController {
    
    @PostMapping("/process")
    public PaymentResponse processPayment(@RequestBody PaymentRequest request) {
        return new PaymentResponse(
            "txn-" + UUID.randomUUID(),
            request.amount(),
            "APPROVED",
            "Payment processed successfully",
            Instant.now()
        );
    }
    
    public record PaymentRequest(
        String accountNumber,
        BigDecimal amount,
        String currency
    ) {}
    
    @EncryptBody // Cifra el response completo como JWE
    public record PaymentResponse(
        String transactionId,
        BigDecimal amount,
        String status,
        String message,
        Instant timestamp
    ) {}
}
```

**Response HTTP con body cifrado completo:**
```http
HTTP/1.1 200 OK
Content-Type: application/jwe

eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6ImNsaWVudC1lbmMtN2E4Yi4uLiJ9.
.yc_YXpZcN_F9P3Qx.
K7bQ9xJ2v_encrypted_payload_XnF4M8pLsT.
zR4wK9jD3mN5vA
```

**Contenido descifrado del JWE:**
```json
{
  "transactionId": "txn-123e4567-e89b-12d3-a456-426614174000",
  "amount": 1000.00,
  "status": "APPROVED",
  "message": "Payment processed successfully",
  "timestamp": "2025-11-11T10:30:00Z"
}
```

**Diferencias entre `@EncryptField` y `@EncryptBody`:**

| Característica | `@EncryptField` | `@EncryptBody` |
|----------------|-----------------|----------------|
| Aplicación | Sobre campos del DTO/Record | Sobre DTO/Record de respuesta |
| Alcance | Campos individuales | Response completo |
| Estructura | JSON con sobre `_e2e_crypto` | JWE puro |
| Content-Type | `application/json` | `application/jwe` |
| Campos visibles | Campos públicos + sobre | Ninguno |
| Uso recomendado | Datos mixtos (públicos + sensibles) | Todo el response es sensible |

## Gestión de Claves
### Estados de Clave
| Estado | Descripción |
|--------|-------------|
| `ACTIVE` | Clave actual para cifrado de salida |
| `PREVIOUS` | Clave anterior, aún válida para descifrado |
| `INACTIVE` | Clave obsoleta, rechazada |
### Rotación de Claves

La rotación de claves es iniciada por el **microservicio** cuando recibe notificación de **hashpytkeys**. El microservicio consulta y actualiza su cache local con el bundle de claves.

#### Configuración de Consul (`ConsulRegistrationConfig`)

El microservicio se registra en Consul con metadata y tag `crypto-enabled`:

```java
@Configuration
public class ConsulRegistrationConfig {

    @Bean
    ConsulRegistrationCustomizer addCryptoMeta() {
        return (ConsulRegistration registration) -> {
            // Añade metainformación y etiqueta indicando que tiene cifrado habilitado
            registration.getService().getMeta().put("crypto", "enabled");
            registration.getService().getTags().add("crypto-enabled");
        };
    }
}
```

**Propósito del tag `crypto-enabled`:**

- Identifica servicios con capacidad de cifrado E2E
- Usado por hashpytkeys para descubrir servicios compatibles
- La metadata `crypto: enabled` complementa la información

#### Endpoint Interno de Rotación

El microservicio expone `/.internal/key-rotation` que hashpytkeys invoca para notificar la rotación:

```java
@RestController
@RequestMapping("/.internal/key-rotation")
public class KeyRotationLaunchController {

    private final KeyRotationBroadcaster keyRotationBroadcaster;
    private final ApplicationContext applicationContext;

    @PostMapping
    public ResponseEntity<String> launchKeyRotation() {
        log.info("Starting key rotation process...");
        try {
            keyRotationBroadcaster.broadcast();
            return ResponseEntity.ok("Key rotation process completed successfully.");
        } catch (Exception e) {
            AvailabilityChangeEvent.publish(applicationContext, LivenessState.BROKEN);
            AvailabilityChangeEvent.publish(applicationContext, ReadinessState.REFUSING_TRAFFIC);
            return ResponseEntity.status(500).body("Error during key rotation: " + e.getMessage());
        }
    }
}
```

#### Proceso de Actualización (`KeyRotationBroadcaster`)

Cuando se invoca el endpoint, `KeyRotationBroadcaster.broadcast()` ejecuta:

1. **Consulta Consul** para encontrar instancias activas de `hashpytkeys`
2. **Obtiene el bundle de claves** llamando al endpoint de hashpytkeys:
   ```
   GET http://{hashpytkeys-host}:{port}{contextPath}/homebanking/keys/.internal/e2e/bundle?service=global&idClient=1234
   ```
3. **Actualiza el cache local** con `keyCacheService.loadEnvelope(envelope)`
4. **Verifica** las nuevas claves activas

**Código real de `KeyRotationBroadcaster`:**

```java
public void broadcast() {
    var healthRequest = HealthServicesRequest.newBuilder()
            .setPassing(true)
            .build();

    var activeServices = consulClient.getHealthServices("hashpytkeys", healthRequest)
            .getValue()
            .stream()
            .toList();
            
    if (activeServices.isEmpty()) {
        throw new IllegalStateException("No active 'hashpytkeys' services found.");
    }
    
    var healthInstance = activeServices.stream().findFirst()
            .orElseThrow();
    this.getRotationKeys(healthInstance, "1234");
}

private void getRotationKeys(HealthService h, String idClient) {
    var address = Optional.ofNullable(h.getService().getAddress())
            .orElse(h.getNode().getAddress());
    var port = h.getService().getPort();
    var contextPath = Optional.ofNullable(h.getService().getMeta().get("contextPath"))
            .orElse("");

    var url = String.format(
            "http://%s:%d%s/homebanking/keys/.internal/e2e/bundle?service=%s&idClient=%s",
            address, port, contextPath, "global", idClient
    );

    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

    if (response.statusCode() == 200) {
        Map<String, Object> envelope = objectMapper.readValue(response.body(), new TypeReference<>() {});
        keyCacheService.loadEnvelope(envelope);
    }
}
```

**Flujo completo de rotación:**

1. hashpytkeys ejecuta rotación programada en su BD (ACTIVE→PREVIOUS→INACTIVE)
2. hashpytkeys identifica servicios registrados con tag `crypto-enabled` en Consul
3. hashpytkeys llama `POST /.internal/key-rotation` en cada microservicio
4. `KeyRotationLaunchController` recibe la notificación
5. `KeyRotationBroadcaster.broadcast()` consulta Consul para ubicar hashpytkeys
6. Llama al endpoint bundle: `GET /homebanking/keys/.internal/e2e/bundle`
7. `KeyCacheService` actualiza su cache con el nuevo envelope de claves
8. Microservicio responde `200 OK` (o marca servicio como `BROKEN` si falla)

**Configuración application.yml:**

```yaml
spring:
  application:
    name: my-service
  cloud:
    consul:
      host: localhost
      port: 8500
      discovery:
        service-name: ${spring.application.name}
```

**Resumen de componentes:**

| Componente | Función |
|------------|---------|
| `ConsulRegistrationConfig` | Registra servicio con tag `crypto-enabled` y metadata |
| `KeyRotationLaunchController` | Endpoint `/.internal/key-rotation` que recibe notificación |
| `KeyRotationBroadcaster` | Consulta hashpytkeys y actualiza bundle de claves |
| `KeyCacheService` | Almacena cache local del envelope de claves |
| healthpytkeys→microservicio | Push: hashpytkeys notifica rotación |
| microservicio→hashpytkeys | Pull: microservicio descarga bundle actualizado |
## Endpoints de Infraestructura
### Obtener Clave Pública Activa
```http
GET /enc/key
```
### Prueba de Cifrado (Solo desarrollo)
```http
POST /.internal/enc-test/echo
Content-Type: application/json
{"test": "data"}
```
### Generar Claves de Cliente (Solo desarrollo)
```http
GET /.internal/enc-test/client-keys
```
## Configuración
### Dependencia Maven
```xml
<dependency>
    <groupId>com.e2ew</groupId>
    <artifactId>e2e</artifactId>
    <version>0.0.3</version>
</dependency>
```
## Consideraciones de Seguridad
### Claves Privadas
- **NUNCA** exponer claves privadas vía API
- Almacenar en HSM o gestores de secretos (Vault, AWS KMS)
- Rotar periódicamente (recomendado: cada 24-48h)
### Transporte
- Usar HTTPS obligatoriamente en producción
- E2E añade capa adicional, no reemplaza TLS
### Validaciones
- Verificar `kid` en headers JWE/JWS
- Validar algoritmos permitidos (`alg`, `enc`)
- Rechazar claves en estado `INACTIVE`
### Headers Críticos
- `b64: false` → payload NO codificado en base64 (JWS detached)
- `crit: ["b64"]` → extensión crítica que DEBE procesarse
### Decisión del Cliente
- El cliente tiene control total sobre qué cifrar
- Puede elegir entre cifrado total o selectivo
- El sobre `_e2e_crypto` es opcional según necesidades
- La librería soporta ambos modos transparentemente
## Testing
```bash
# Ejecutar tests
mvn test
# Tests específicos de flujo E2E
mvn test -Dtest=CryptoFlowE2ETest
mvn test -Dtest=SignAndCryptFlowE2ETest
```
## Troubleshooting
### Error: "kid ausente en el header JWE"
**Causa:** Request sin `kid` en header JWE  
**Solución:** Incluir `kid` del servidor en header al cifrar
### Error: "alg inesperado"
**Causa:** Algoritmo no soportado  
**Solución:** Usar `ECDH-ES` para JWE y `EdDSA` para JWS
### Error: "enc no permitido"
**Causa:** Método de cifrado no autorizado  
**Solución:** Usar `A256GCM` o `XC20P`
### Error: "Content-Type inválido"
**Causa:** Content-Type incorrecto  
**Solución:** Usar `application/jwe` (cifrado total) o `application/json` (sobre `_e2e_crypto`)
### Error: "No se encuentra el sobre _e2e_crypto"
**Causa:** Request con `Content-Type: application/json` sin el sobre esperado  
**Solución:** Incluir objeto `_e2e_crypto` con campos cifrados o usar `application/jwe`
## Licencia
Propietario: E2EW  
Versión: 0.0.3  
Descripción: Seguridad E2E para HB
## Contacto
Repositorio: Nexus - https://nexus.procesosytecnologia.com/repository/maven-releases/
