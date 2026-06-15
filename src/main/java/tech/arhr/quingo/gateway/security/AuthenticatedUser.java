package tech.arhr.quingo.gateway.security;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Данные пользователя, извлечённые из валидного access-токена.
 */
public record AuthenticatedUser(
        UUID userId,
        UUID sessionId,
        Instant issuedAt,
        List<String> roles,
        String email,
        String username
) {
}
