package com.e2ew.e2e.keys.rotate;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.consul.discovery.ConsulDiscoveryClient;
import org.springframework.context.SmartLifecycle;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.stereotype.Service;

import com.e2ew.e2e.keys.cache.KeyCacheService;
import com.e2ew.e2e.keys.model.RotationInfo;

/**
 * Servicio que sincroniza el bundle de llaves desde una instancia de `hashpytkeys` y
 * programa una "ventana" previa al vencimiento (notAfter) para realizar polling
 * hasta detectar el cambio de `kid` y recargar las llaves en runtime.
 *
 * Flujo principal (resumen):
 * - Carga inicial del bundle y cache local (keyCacheService.loadEnvelope).
 * - Extrae `kid` y `notAfter` de la llave activa.
 * - Programa una ventana que empieza en notAfter - windowBefore.
 * - Dentro de la ventana hace polling periódico con jitter hasta que `kid` cambie.
 * - Si detecta nuevo `kid`, aplica la nueva llave (ya cargada en cache) y reprograma
 *   la siguiente ventana con el nuevo notAfter si está presente.
 */
@Service
@EnableConfigurationProperties(KeyRotationProperties.class)
public class KeyRotationBroadcaster implements SmartLifecycle {
    private static final Logger log = LoggerFactory.getLogger(KeyRotationBroadcaster.class);
    private final ConsulDiscoveryClient consulDiscoveryClient;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KeyCacheService keyCacheService;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicReference<Instant> lastSuccessfulSync = new AtomicReference<>(null);
    private final TaskScheduler keyRotationTaskScheduler;
    private final ReentrantLock refreshLock = new ReentrantLock();

    // cool-downs
    private final AtomicReference<Instant> lastOkRefresh = new AtomicReference<>(Instant.EPOCH);
    private final AtomicReference<Instant> lastFailRefresh = new AtomicReference<>(Instant.EPOCH);

    // tunables simples
    private final Duration okCooldown = Duration.ofSeconds(2);     // si refresqué OK hace <2s, no repito
    private final Duration failCooldown = Duration.ofSeconds(10);  // si fallé hace <10s, no repito
    private final Duration lockWait = Duration.ofMillis(300);      // cuánto espero el lock si otro refresca

    // ---- TTL refresh config ----
    private final Duration ttlRefresh;   // 5m
    private final Duration ttlJitter;    // 0-30s
    private final boolean ttlEnabled;

    private final AtomicReference<ScheduledFuture<?>> ttlFuture = new AtomicReference<>(null);



    public KeyRotationBroadcaster(ConsulDiscoveryClient consulDiscoveryClient,
                                  KeyCacheService keyCacheService,
                                  @Qualifier("keyRotationTaskScheduler") TaskScheduler keyRotationTaskScheduler,
                                  KeyRotationProperties props) {
        this.consulDiscoveryClient = consulDiscoveryClient;
        this.keyCacheService = keyCacheService;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.keyRotationTaskScheduler = keyRotationTaskScheduler;

        // Cargar configuración desde el POJO
        this.ttlRefresh = Duration.ofSeconds(props.getTtlRefreshSeconds()); // 300
        this.ttlJitter  = Duration.ofSeconds(props.getTtlJitterSeconds());  // 30
        this.ttlEnabled = props.isTtlEnabled();
    }

    /**
     * REFRESH BLOQUEANTE: intenta obtener y cargar el bundle desde cualquier instancia saludable.
     * - Ideal para usar como fallback cuando llega un kid desconocido.
     * - No agenda nada; solo hace fetch+load y retorna.
     */
    public RotationInfo refreshNow(String idClient) {
        // Anti-stampede: si otro thread ya está refrescando, espera un poco y retorna lo último.
        // 1) cooldown por éxito reciente
        Instant okAt = lastOkRefresh.get();
        if (Duration.between(okAt, Instant.now()).compareTo(okCooldown) < 0) {
            return new RotationInfo(keyCacheService.getActiveKid(), null);
        }

        // 2) cooldown por fallo reciente
        Instant failAt = lastFailRefresh.get();
        if (Duration.between(failAt, Instant.now()).compareTo(failCooldown) < 0) {
            return new RotationInfo(keyCacheService.getActiveKid(), null);
        }

        boolean acquired = false;
        try {
            // 3) si otro thread ya refresca, espero poquito y listo
            acquired = refreshLock.tryLock(lockWait.toMillis(), TimeUnit.MILLISECONDS);
            if (!acquired) {
                // alguien está refrescando; sigo con lo que haya en cache
                return new RotationInfo(keyCacheService.getActiveKid(), null);
            }

            // 4) doble-check: quizá ya refrescaron mientras yo esperaba el lock
            okAt = lastOkRefresh.get();
            if (Duration.between(okAt, Instant.now()).compareTo(okCooldown) < 0) {
                return new RotationInfo(keyCacheService.getActiveKid(), null);
            }

            var instances = consulDiscoveryClient.getInstances("hashpytkeys");
            if (instances.isEmpty()) {
                throw new IllegalStateException("No active 'hashpytkeys' services found in Consul.");
            }

            // importante: NO te cases con la primera
            var list = new ArrayList<>(instances);
            Collections.shuffle(list);

            Exception lastError = null;
            for (var ins : list) {
                try {
                    RotationInfo info = fetchAndLoadBundle(ins, idClient);
                    lastOkRefresh.set(Instant.now());
                    return info;
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("refreshNow interrupted", ie);
                } catch (Exception e) {
                    lastError = e;
                    log.warn("refreshNow failed from {}:{} - {}", ins.getHost(), ins.getPort(), e.getMessage());
                }
            }

            lastFailRefresh.set(Instant.now());
            throw new IllegalStateException("refreshNow: all instances failed", lastError);

        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("refreshNow interrupted while waiting lock", ie);
        } catch (RuntimeException re) {
            lastFailRefresh.set(Instant.now());
            throw re;
        } finally {
            if (acquired) refreshLock.unlock();
        }

    }

    public void startTtlRefresh(String idClient) {
        if (!ttlEnabled) {
            log.info("TTL refresh disabled.");
            return;
        }
        scheduleNextTtl(idClient);
    }

    private void scheduleNextTtl(String idClient) {
        long baseMs = ttlRefresh.toMillis();

        long jitterMs = (ttlJitter.toMillis() > 0)
                ? ThreadLocalRandom.current().nextLong(0, ttlJitter.toMillis() + 1)
                : 0L;

        Instant nextRun = Instant.now().plusMillis(baseMs + jitterMs);

        ScheduledFuture<?> future = keyRotationTaskScheduler.schedule(() -> {
            try {
                // refreshNow ya está protegido con lock+cooldown (anti-stampede)
                RotationInfo info = refreshNow(idClient);
                log.debug("TTL refresh executed. activeKid={}",
                        info.kid() != null ? info.kid() : keyCacheService.getActiveKid());
            } catch (Exception e) {
                log.warn("TTL refresh failed: {}", e.getMessage());
            } finally {
                // reprograma siempre
                scheduleNextTtl(idClient);
            }
        }, nextRun);

        ScheduledFuture<?> prev = ttlFuture.getAndSet(future);
        if (prev != null) {
            prev.cancel(false);
        }

        log.info("Next TTL refresh scheduled at {} (base={}s jitter<= {}s)",
                nextRun, ttlRefresh.toSeconds(), ttlJitter.toSeconds());
    }


    public void stopTtlRefresh() {
        ScheduledFuture<?> f = ttlFuture.getAndSet(null);
        if (f != null) f.cancel(false);
    }


    /**
     * Llama al endpoint que devuelve el bundle de llaves, carga el envelope en cache y
     * devuelve (kid, notAfter) de la llave activa si se puede extraer.
     */
    private RotationInfo fetchAndLoadBundle(ServiceInstance instance, String idClient) throws IOException, InterruptedException {
        var address = instance.getHost();
        var port = instance.getPort();
        var metadata = instance.getMetadata();
        var contextPath = (metadata != null) ? metadata.getOrDefault("contextPath", "") : "";

        var url = String.format(
                "http://%s:%d%s/homebanking/keys/.internal/e2e/bundle?service=%s&idClient=%s",
                address, port, contextPath, "global", idClient
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            String body = response.body();
            // Deserializar directamente al record KeysBundle para extraer información con precisión
            var bundle = objectMapper.readValue(body, KeyBundleRecords.KeysBundle.class);
            // Mantener compatibilidad: cargar el envelope como Map para KeyCacheService
            Map<String, Object> envelope = objectMapper.readValue(body, new TypeReference<>() {});
            keyCacheService.loadEnvelope(envelope);
            lastSuccessfulSync.set(Instant.now());
            log.info("Loaded bundle service={} version={} kidActive={}", bundle.service(), bundle.version(), bundle.kidActive());

            // Extraer kidActivo y notAfter del key marcado como ACTIVE o por kidActive
            RotationInfo found = extractActiveFromBundle(bundle);
            if (found != null) return found;

            // Fallback: usar el kid activo de keyCacheService si está disponible, sin notAfter
            return new RotationInfo(keyCacheService.getActiveKid(), null);
        } else {
            log.error("Failed to fetch keys bundle from {}: HTTP {}", url, response.statusCode());
            throw new IOException("Failed to fetch keys bundle: HTTP " + response.statusCode());
        }
    }

    // Extrae active kid y notAfter del KeysBundle record (package-private para pruebas)
    RotationInfo extractActiveFromBundle(KeyBundleRecords.KeysBundle bundle) {
        if (bundle == null)
            return null;
        String kidActive = bundle.kidActive();
        if (kidActive != null && bundle.keys() != null) {
            for (KeyBundleRecords.KeyEntry entry : bundle.keys()) {
                if (kidActive.equals(entry.kid()) && entry.state() != null && "ACTIVE".equals(entry.state())) {
                    try {
                        return new RotationInfo(entry.kid(),
                                entry.notAfter() != null ? Instant.parse(entry.notAfter()) : null);
                    } catch (DateTimeParseException e) {
                        return new RotationInfo(entry.kid(), null);
                    }
                }
            }
        }
        return null;
    }

    /* SmartLifecycle implementation */
    @Override
    public void start() {
        log.info("Starting KeyRotationBroadcaster...");
        refreshNow("global");
        startTtlRefresh("global");
        running.set(true);
    }

    @Override
    public void stop() {
        stopTtlRefresh();
        running.set(false);
    }

    @Override
    public boolean isRunning() {
        return running.get();
    }

    @Override
    public int getPhase() {
        return -1000;
    }

    @Override
    public void stop(Runnable callback) {
        stop();
        callback.run();
    }

    // getter para permitir que un HealthIndicator separado consulte la última sincronización
    public Instant getLastSuccessfulSync() {
        return lastSuccessfulSync.get();
    }
}
