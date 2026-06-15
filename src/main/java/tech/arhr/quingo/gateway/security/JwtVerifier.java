package tech.arhr.quingo.gateway.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Проверяет подпись и срок действия access-токена публичным ключом auth-service.
 */
@Component
public class JwtVerifier {

    @Value("${auth-service.public-key-url}")
    private String publicKeyUrl;

    private JWTVerifier verifier;

    @PostConstruct
    public void init() {
        try {
            String publicKeyPem = WebClient.create()
                    .get()
                    .uri(publicKeyUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            ECPublicKey publicKey = parsePublicKey(publicKeyPem);
            verifier = JWT.require(Algorithm.ECDSA256(publicKey, null)).build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to fetch/parse JWT public key from " + publicKeyUrl, e);
        }
    }

    /**
     * Проверяет токен и возвращает данные пользователя.
     *
     * @throws InvalidTokenException при невалидном токене
     */
    public AuthenticatedUser verify(String token) {
        DecodedJWT jwt;
        try {
            jwt = verifier.verify(token);
        } catch (Exception e) {
            throw new InvalidTokenException("Invalid access token");
        }

        if (!"access".equals(jwt.getClaim("typ").asString())) {
            throw new InvalidTokenException("Token is not access");
        }

        return new AuthenticatedUser(
                UUID.fromString(jwt.getSubject()),
                UUID.fromString(jwt.getClaim("sid").asString()),
                jwt.getIssuedAt().toInstant(),
                jwt.getClaim("roles").asList(String.class),
                jwt.getClaim("email").asString(),
                jwt.getClaim("username").asString()
        );
    }

    private ECPublicKey parsePublicKey(String pem) throws Exception {
        String cleaned = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(cleaned);
        KeyFactory kf = KeyFactory.getInstance("EC");
        return (ECPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
    }
}
