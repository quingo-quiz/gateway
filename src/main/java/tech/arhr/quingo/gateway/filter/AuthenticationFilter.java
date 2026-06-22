package tech.arhr.quingo.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tech.arhr.quingo.gateway.security.AuthenticatedUser;
import tech.arhr.quingo.gateway.security.InvalidTokenException;
import tech.arhr.quingo.gateway.security.JwtVerifier;
import tech.arhr.quingo.gateway.security.TokenRevocationService;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Централизованная проверка авторизации для всех проксируемых запросов, кроме запросов к Auth Service.
 * При успехе в запрос добавляются заголовки с информацией о пользователе.
 * Входящие одноимённые заголовки всегда перезаписываются для избежания подделывания
 */
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private static final String USER_ID = "X-User-Id";
    private static final String USER_EMAIL = "X-User-Email";
    private static final String USER_ROLES = "X-User-Roles";
    private static final String SESSION_ID = "X-Session-Id";

    private final JwtVerifier jwtVerifier;
    private final TokenRevocationService revocationService;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (!path.startsWith("/api/") || request.getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        if (isPublic(path)) {
            return chain.filter(exchange.mutate().request(stripUserHeaders(request)).build());
        }

        String token = extractToken(request);
        if (token == null) {
            return unauthorized(exchange, "Authentication required");
        }

        AuthenticatedUser user;
        try {
            user = jwtVerifier.verify(token);
        } catch (InvalidTokenException e) {
            return unauthorized(exchange, e.getMessage());
        }

        return revocationService.isBlocked(user.userId(), user.sessionId(), user.issuedAt())
                .flatMap(blocked -> blocked
                        ? unauthorized(exchange, "Token is revoked")
                        : chain.filter(exchange.mutate().request(withUserHeaders(request, user)).build()));
    }

    /**
     * Публичные пути, не требующие авторизации.
     */
    private boolean isPublic(String path) {
        return path.startsWith("/api/auth") || path.startsWith("/api/catalog");
    }

    private String extractToken(ServerHttpRequest request) {
        HttpCookie cookie = request.getCookies().getFirst("access_token");
        if (cookie != null) {
            return cookie.getValue();
        }
        String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return null;
    }

    private ServerHttpRequest stripUserHeaders(ServerHttpRequest request) {
        return request.mutate()
                .headers(headers -> {
                    headers.remove(USER_ID);
                    headers.remove(USER_EMAIL);
                    headers.remove(USER_ROLES);
                    headers.remove(SESSION_ID);
                })
                .build();
    }

    private ServerHttpRequest withUserHeaders(ServerHttpRequest request, AuthenticatedUser user) {
        return request.mutate()
                .headers(headers -> {
                    headers.set(USER_ID, user.userId().toString());
                    headers.set(USER_ROLES, String.join(",", user.roles()));
                    headers.set(SESSION_ID, user.sessionId().toString());
                    if (user.email() != null) {
                        headers.set(USER_EMAIL, user.email());
                    } else {
                        headers.remove(USER_EMAIL);
                    }
                })
                .build();
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("statusMessage", HttpStatus.UNAUTHORIZED.getReasonPhrase());
        body.put("message", message);
        body.put("path", exchange.getRequest().getURI().getPath());
        body.put("method", exchange.getRequest().getMethod().name());
        body.put("timestamp", Instant.now().toString());

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (Exception e) {
            bytes = new byte[0];
        }
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
