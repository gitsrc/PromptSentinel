package io.promptsentinel.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.Map;

/**
 * Result of {@code GET /version}.
 *
 * @param service  service identifier (always {@code "promptsentinel"})
 * @param version  semantic version of the running service
 * @param scanners map of scanner name to availability flag (never {@code null})
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record VersionResult(
        @JsonProperty("service") String service,
        @JsonProperty("version") String version,
        @JsonProperty("scanners") Map<String, Boolean> scanners) {

    @JsonCreator
    public VersionResult {
        scanners = (scanners == null)
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(Map.copyOf(scanners));
    }
}
