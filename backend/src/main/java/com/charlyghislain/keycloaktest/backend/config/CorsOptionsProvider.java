package com.charlyghislain.keycloaktest.backend.config;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.util.List;
import java.util.Set;

/**
 * Created by cghislai on 11/02/17.
 */

@ApplicationScoped
public class CorsOptionsProvider {

    @Inject
    @ConfigProperty(name = "be.valuya.retire.cors.allowedHosts", defaultValue = "*")
    private List<String> allowedOrigins;
    @Inject
    @ConfigProperty(name = "be.valuya.retire.cors.allowedHeaders", defaultValue = "cache-control,content-type,accept,accept-charset,authorization,X-Requested-With,ngsw-bypass")
    private List<String> allowedHeaders;
    @Inject
    @ConfigProperty(name = "be.valuya.retire.cors.exposedHeaders", defaultValue = "content-encoding,content-length")
    private List<String> exposedHeaders;

    @PostConstruct()
    public void init() {
    }

    public List<String> getAllowedOrigins() {
        return this.allowedOrigins;
    }

    public Set<String> getAllowedMethods() {
        return Set.of(
                HttpMethod.GET, HttpMethod.PUT,
                HttpMethod.POST, HttpMethod.DELETE
        );
    }

    public List<String> getAllowedHeaders() {
        return allowedHeaders;
    }

    public boolean isWsCorsAllowCredentials() {
        return true;
    }

    public int getCorsMaxAge() {
        return 0;
    }

    public List<String> getExposedHeaders() {
        return exposedHeaders;
    }
}
