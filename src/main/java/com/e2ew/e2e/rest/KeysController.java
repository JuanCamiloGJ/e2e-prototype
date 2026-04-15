package com.e2ew.e2e.rest;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.e2ew.e2e.keys.cache.KeyCacheService;

@RestController
@RequestMapping("/enc/key")
public class KeysController {

    private final KeyCacheService keyCacheService;

    public KeysController(KeyCacheService keyCacheService) {
        this.keyCacheService = keyCacheService;
    }

    @GetMapping
    public ResponseEntity<Object> getApiKey() {
        try {
            var octet = keyCacheService.getActivePublicKey();
            var response = Map.of("activeKey", octet.toJSONString());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error retrieving API key: " + e.getMessage());
        }
    }






}
