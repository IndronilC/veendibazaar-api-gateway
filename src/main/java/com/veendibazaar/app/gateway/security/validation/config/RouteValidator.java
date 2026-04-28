package com.veendibazaar.app.gateway.security.validation.config;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    // Public endpoints (NO JWT required)
    private static final List<String> OPEN_API_ENDPOINTS = List.of(
            "/api/v1/auth/authenticate",
            "/api/v1/auth/activate-token",
            "/api/v1/auth/register",
            "/api/v1/auth/refresh"
    );

    // Predicate to check if request is secured
    public Predicate<ServerHttpRequest> isSecured =
            request -> OPEN_API_ENDPOINTS
                    .stream()
                    .noneMatch(uri -> request.getURI().getPath().contains(uri));
}
