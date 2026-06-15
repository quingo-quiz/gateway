package tech.arhr.quingo.gateway.security;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Проверяет, не отозван ли access-токен. Метки отзыва пишет auth-service в Redis
 */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final String SESSION_PREFIX = "valid_after:session:";
    private static final String USER_PREFIX = "valid_after:user:";

    private final ReactiveRedisTemplate<String, Instant> revocationTimeRedisTemplate;

    public Mono<Boolean> isBlocked(UUID userId, UUID sessionId, Instant issuedAt) {
        Mono<Boolean> bySession = isRevoked(SESSION_PREFIX + sessionId, issuedAt);
        Mono<Boolean> byUser = isRevoked(USER_PREFIX + userId, issuedAt);

        return Mono.zip(bySession, byUser, (s, u) -> s || u);
    }

    private Mono<Boolean> isRevoked(String key, Instant issuedAt) {
        return revocationTimeRedisTemplate.opsForValue().get(key)
                .map(revocationTime -> !issuedAt.isAfter(revocationTime))
                .defaultIfEmpty(false);
    }
}
