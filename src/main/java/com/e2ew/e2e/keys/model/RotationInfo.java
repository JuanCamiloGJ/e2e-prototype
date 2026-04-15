package com.e2ew.e2e.keys.model;

import java.time.Instant;

public record RotationInfo(String kid, Instant notAfter) {
}
