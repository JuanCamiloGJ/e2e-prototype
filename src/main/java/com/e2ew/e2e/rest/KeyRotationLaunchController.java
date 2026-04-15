package com.e2ew.e2e.rest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.e2ew.e2e.keys.rotate.KeyRotationBroadcaster;

@RestController
@RequestMapping("/.internal/key-rotation")
public class KeyRotationLaunchController {

    private static final Logger log = LoggerFactory.getLogger(KeyRotationLaunchController.class);
    private final KeyRotationBroadcaster keyRotationBroadcaster;
    private final ApplicationContext applicationContext;

    public KeyRotationLaunchController(KeyRotationBroadcaster keyRotationBroadcaster,
            ApplicationContext applicationContext) {
        this.keyRotationBroadcaster = keyRotationBroadcaster;
        this.applicationContext = applicationContext;
    }

    @PostMapping
    public ResponseEntity<String> launchKeyRotation() {
        // Lógica para iniciar la rotación de claves
        log.info("Starting key rotation process...");
        try {
            keyRotationBroadcaster.startTtlRefresh("x");
            return ResponseEntity.ok("Key rotation process completed successfully.");

        } catch (Exception e) {
            AvailabilityChangeEvent.publish(applicationContext, LivenessState.BROKEN);
            AvailabilityChangeEvent.publish(applicationContext, ReadinessState.REFUSING_TRAFFIC);
            return ResponseEntity.status(500).body("Error during key rotation: " + e.getMessage());
        }

    }

}
