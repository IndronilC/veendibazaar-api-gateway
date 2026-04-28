package com.veendibazaar.app.gateway.security.validation.config.filter;


import com.veendibazaar.app.gateway.security.validation.config.RouteValidator;
import com.veendibazaar.app.gateway.security.validation.config.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    @Autowired
    private RouteValidator routeValidator;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();

        // ✅ Apply only to secured routes
        if (routeValidator.isSecured.test(request)) {

            // 1. Check Authorization header
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return onError(exchange, "Missing or invalid Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            try {
                // 2. Validate token
                Claims claims = jwtUtil.validateToken(token);

                String userId = claims.getSubject();

                // 3. Extract roles safely
                Object rolesObject = claims.get("roles");

                final List<String> roles;

                if (rolesObject instanceof List<?>) {
                    roles = ((List<?>) rolesObject)
                            .stream()
                            .map(Object::toString)
                            .toList();
                } else {
                    roles = List.of();
                }
                // 4. Mutate request (Zero Trust: overwrite headers)
                ServerHttpRequest mutatedRequest = request.mutate()
                        .headers(headers -> {
                            headers.remove("X-User-Id");
                            headers.remove("X-Roles");

                            headers.add("X-User-Id", userId);
                            headers.add("X-Roles", String.join(",", roles));
                        })
                        .build();

                // 5. Continue filter chain
                return chain.filter(exchange.mutate().request(mutatedRequest).build());

            } catch (Exception ex) {
                return onError(exchange, "Invalid or expired JWT", HttpStatus.UNAUTHORIZED);
            }
        }

        return chain.filter(exchange);
    }

    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);

        // Optional: add message body later if needed
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // run early
    }
}
