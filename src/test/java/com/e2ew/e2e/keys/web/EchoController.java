package com.e2ew.e2e.keys.web;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.e2ew.e2e.keys.security.annotations.EncryptField;
import com.e2ew.e2e.rest.EncryptionTestController;

@RestController
public class EchoController {
    public record EchoResponseEntity(String body, @EncryptField String anotherField) {
    }

    @PostMapping(value = "/echo", consumes = {MediaType.APPLICATION_JSON_VALUE,
            "application/jwe"}, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<EncryptionTestController.EchoResponseEntity> echo(@RequestBody String body) {
        return ResponseEntity.ok(new EncryptionTestController.EchoResponseEntity(body,
                "texto encriptado")); // devolvemos EXACTO lo que llega al controller (post-filtro)
    }
}
