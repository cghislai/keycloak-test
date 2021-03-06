package com.charlyghislain.keycloaktest.backend.config;


import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Handle CORS preflight (OPTIONS) requests.
 *
 * @author cghislai
 */
@Provider
@PreMatching
@Priority(Priorities.HEADER_DECORATOR)
public class CrossOriginResourceSharingPreflightRequestFilter implements ContainerRequestFilter {

    @Inject
    private CorsOptionsProvider corsOptionsProvider;
    @Inject
    @Claim(value = "allowed-origins")
    private ClaimValue<Optional<List<String>>> tokenAllowedOriginsClaim;

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String method = requestContext.getMethod();
        MultivaluedMap<String, String> headers = requestContext.getHeaders();
        boolean corsPreflightRequest = CorsUtils.isCorsPreflightRequest(method, headers);
        if (!corsPreflightRequest) {
            return;
        }

        List<String> configurationOrigins = corsOptionsProvider.getAllowedOrigins();
        List<String> allowedOrigins = tokenAllowedOriginsClaim
                .getValue()
                .map(tokenOrigins -> tokenOrigins.stream().filter(configurationOrigins::contains).collect(Collectors.toList()))
                .orElse(configurationOrigins);

        boolean originAllowed = CorsUtils.isAllowedOrigin(headers, allowedOrigins);
        if (!originAllowed) {
            abortWitError(requestContext, "Origin not allowed");
            return;
        }

        Set<String> allowedMethods = corsOptionsProvider.getAllowedMethods();
        boolean methodAllowed = CorsUtils.isRequestedMethodAllowed(headers, allowedMethods);
        if (!methodAllowed) {
            abortWitError(requestContext, "Method not allowed");
            return;
        }

        List<String> allowedHeaders = corsOptionsProvider.getAllowedHeaders();
        boolean requestedHeadersAllowed = CorsUtils.isRequestedHeadersAllowed(headers, allowedHeaders);
        if (!requestedHeadersAllowed) {
            abortWitError(requestContext, "Some requested header not allowed");
            return;
        }

        boolean wsCorsAllowCredentials = corsOptionsProvider.isWsCorsAllowCredentials();
        int wsCorsMaxAge = corsOptionsProvider.getCorsMaxAge();
        String requestOrigin = CorsUtils.getRequestOrigin(headers).orElseThrow(IllegalStateException::new);

        String allowedMethodsResponseHeader = String.join(",", allowedMethods);
        String allowedHeadersResponseHeader = String.join(",", allowedHeaders);

        Response.ResponseBuilder responseBuilder = Response.ok()
                .header("Access-Control-Allow-Origin", requestOrigin)
                .header("Access-Control-Allow-Methods", allowedMethodsResponseHeader)
                .header("Access-Control-Allow-Headers", allowedHeadersResponseHeader)
                .header("Access-Control-Max-Age", wsCorsMaxAge);
        if (wsCorsAllowCredentials) {
            responseBuilder.header("Access-Control-Allow-Credentials", "true");
        }
        Response response = responseBuilder.build();
        requestContext.abortWith(response);
    }

    private void abortWitError(ContainerRequestContext requestContext, String reason) {
        Response response = Response.status(Response.Status.NOT_ACCEPTABLE)
                .header("X-Gestemps-Cors-Rejection-Reason", reason)
                .build();
        requestContext.abortWith(response);
    }
}
