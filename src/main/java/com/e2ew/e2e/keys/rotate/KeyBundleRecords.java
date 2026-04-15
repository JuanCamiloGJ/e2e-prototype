package com.e2ew.e2e.keys.rotate;

import java.util.List;

// Records para mapear directamente el JSON del bundle de llaves
public class KeyBundleRecords {

    public record KeysBundle(String service, long version, String kidActive, List<KeyEntry> keys) {}

    public record KeyEntry(
            String kid,
            String kty,
            String crv,
            String use,
            String state,
            String notAfter,
            PublicJwk publicJwk,
            PrivateJwk privateJwk
    ) {}

    public record PublicJwk(String kty, String crv, String kid, String x) {}

    public record PrivateJwk(String kty, String d, String crv, String kid, String x) {}
}
