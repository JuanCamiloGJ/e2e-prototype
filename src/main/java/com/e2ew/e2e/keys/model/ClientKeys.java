package com.e2ew.e2e.keys.model;

import com.nimbusds.jose.jwk.OctetKeyPair;

public record ClientKeys(String clientId, OctetKeyPair pubKeySignature, OctetKeyPair pubKeyEncryption) {
}
