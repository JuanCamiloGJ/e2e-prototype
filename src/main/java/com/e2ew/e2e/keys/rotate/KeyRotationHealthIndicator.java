    package com.e2ew.e2e.keys.rotate;

    import java.time.Duration;
    import java.time.Instant;

    import org.slf4j.Logger;
    import org.slf4j.LoggerFactory;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
    import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
    import org.springframework.boot.health.contributor.Health;
    import org.springframework.boot.health.contributor.HealthIndicator;
    import org.springframework.stereotype.Component;

    @Component
    @ConditionalOnClass(HealthIndicator.class)
    @ConditionalOnBean(KeyRotationBroadcaster.class)
    public class KeyRotationHealthIndicator implements HealthIndicator {
        private static final Logger log = LoggerFactory.getLogger(KeyRotationHealthIndicator.class);

        private final KeyRotationBroadcaster broadcaster;
        private final Duration maxAge;

        public KeyRotationHealthIndicator(KeyRotationBroadcaster broadcaster,
                                          @Value("${keys.rotation.health-max-age-minutes:1800}") long maxAgeMinutes) {
            this.broadcaster = broadcaster;
            this.maxAge = Duration.ofMinutes(maxAgeMinutes);
        }

        @Override
        public Health health() {
            Instant last = broadcaster.getLastSuccessfulSync();
            if (last == null) {
                log.debug("KeyRotation health: never synced");
                return Health.down().withDetail("reason", "never-synced").build();
            }

            Duration age = Duration.between(last, Instant.now());
            if (age.compareTo(maxAge) > 0) {
                log.warn("KeyRotation health: last sync too old (ageSeconds={})", age.getSeconds());
                return Health.outOfService()
                        .withDetail("lastSync", last.toString())
                        .withDetail("ageSeconds", age.getSeconds())
                        .build();
            }

            return Health.up()
                    .withDetail("lastSync", last.toString())
                    .withDetail("ageSeconds", age.getSeconds())
                    .build();
        }
    }