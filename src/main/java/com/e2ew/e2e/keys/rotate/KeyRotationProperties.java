package com.e2ew.e2e.keys.rotate;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * POJO para agrupar las propiedades de ventana/polling de rotación de llaves.
 * Prefijo: keys.rotation
 */
@ConfigurationProperties(prefix = "keys.rotation")
public class KeyRotationProperties {

    // segundos antes de notAfter para empezar a pollear (default 120 = 2 minutos)
    private long windowBeforeSeconds = 120;

    // intervalo base de polling en segundos (default 30s)
    private long pollIntervalSeconds = 30;

    // jitter máximo en segundos (default 5s)
    private long jitterMaxSeconds = 5;

    // duración máxima adicional de la ventana en minutos (default 10m)
    private long maxWindowDurationMinutes = 10;

    // tope de intentos dentro de la ventana
    private int maxAttempts = 20;
//    ttl
    private long ttlRefreshSeconds = 300;   // 5 min
    private long ttlJitterSeconds = 30;     // 0-30s
    private boolean ttlEnabled = true;

    public long getWindowBeforeSeconds() {
        return windowBeforeSeconds;
    }

    public void setWindowBeforeSeconds(long windowBeforeSeconds) {
        this.windowBeforeSeconds = windowBeforeSeconds;
    }

    public long getPollIntervalSeconds() {
        return pollIntervalSeconds;
    }

    public void setPollIntervalSeconds(long pollIntervalSeconds) {
        this.pollIntervalSeconds = pollIntervalSeconds;
    }

    public long getJitterMaxSeconds() {
        return jitterMaxSeconds;
    }

    public void setJitterMaxSeconds(long jitterMaxSeconds) {
        this.jitterMaxSeconds = jitterMaxSeconds;
    }

    public long getMaxWindowDurationMinutes() {
        return maxWindowDurationMinutes;
    }

    public void setMaxWindowDurationMinutes(long maxWindowDurationMinutes) {
        this.maxWindowDurationMinutes = maxWindowDurationMinutes;
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public void setMaxAttempts(int maxAttempts) {
        this.maxAttempts = maxAttempts;
    }

    public boolean isTtlEnabled() {
        return ttlEnabled;
    }

    public void setTtlEnabled(boolean ttlEnabled) {
        this.ttlEnabled = ttlEnabled;
    }

    public long getTtlJitterSeconds() {
        return ttlJitterSeconds;
    }

    public void setTtlJitterSeconds(long ttlJitterSeconds) {
        this.ttlJitterSeconds = ttlJitterSeconds;
    }

    public long getTtlRefreshSeconds() {
        return ttlRefreshSeconds;
    }

    public void setTtlRefreshSeconds(long ttlRefreshSeconds) {
        this.ttlRefreshSeconds = ttlRefreshSeconds;
    }
}
