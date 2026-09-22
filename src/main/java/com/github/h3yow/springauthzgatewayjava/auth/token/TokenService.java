package com.github.h3yow.springauthzgatewayjava.auth.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.github.h3yow.springauthzgatewayjava.config.AuthSecurityProperties;
import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 无状态令牌（HMAC-SHA256 签名）+ 服务端登记簿：
 * - 访问令牌携带 jti，校验时除签名与有效期外还必须在登记簿中（未撤销）；
 * - 刷新令牌为不透明随机串，刷新即轮换：旧刷新令牌被原子消费，旧访问令牌同步撤销；
 * - 并发刷新同一刷新令牌时仅一个请求成功，其余得到一致的失败结果，不会重复签发。
 * 签名密钥在本地启动时随机生成，重启即全部失效（见 README）。
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    public record ValidatedToken(String username, String jti) {
    }

    private record AccessGrant(String username, Instant expiresAt) {
    }

    private record RefreshGrant(String username, Instant expiresAt) {
    }

    private final ConcurrentHashMap<String, AccessGrant> accessGrants = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RefreshGrant> refreshGrants = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();
    private final SecureRandom random = new SecureRandom();
    private final byte[] secret = new byte[32];
    private final AuthSecurityProperties props;
    private final Clock clock;

    public TokenService(AuthSecurityProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
        random.nextBytes(secret);
    }

    public TokenPair issue(String username) {
        Instant now = Instant.now(clock);
        String jti = UUID.randomUUID().toString();
        Instant accessExp = now.plus(props.getAccessTokenTtl());
        accessGrants.put(jti, new AccessGrant(username, accessExp));

        String refreshToken = newOpaque();
        refreshGrants.put(refreshToken, new RefreshGrant(username, now.plus(props.getRefreshTokenTtl())));

        String accessToken = buildAccessToken(username, jti, now, accessExp);
        log.info("token pair issued user={} jti={} refresh={}", username, jti, Masking.prefix(refreshToken));
        return new TokenPair(accessToken, refreshToken, props.getAccessTokenTtl().toSeconds());
    }

    /** 校验访问令牌：签名、有效期、登记簿三者缺一即拒绝。 */
    public Optional<ValidatedToken> validate(String accessToken) {
        if (accessToken == null) {
            return Optional.empty();
        }
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) {
                return Optional.empty();
            }
            String signed = parts[0] + "." + parts[1];
            if (!MessageDigest.isEqual(sign(signed), B64D.decode(parts[2]))) {
                return Optional.empty();
            }
            JsonNode payload = mapper.readTree(B64D.decode(parts[1]));
            String jti = payload.get("jti").asText();
            String username = payload.get("sub").asText();
            Instant exp = Instant.ofEpochSecond(payload.get("exp").asLong());
            if (!exp.isAfter(Instant.now(clock))) {
                return Optional.empty();
            }
            AccessGrant grant = accessGrants.get(jti);
            if (grant == null || !grant.username().equals(username)) {
                // 已撤销或从未签发
                return Optional.empty();
            }
            return Optional.of(new ValidatedToken(username, jti));
        } catch (RuntimeException | java.io.IOException e) {
            return Optional.empty();
        }
    }

    /** 刷新轮换：原子消费旧刷新令牌，仅一个并发调用者能成功。 */
    public Optional<TokenPair> refresh(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        RefreshGrant grant = refreshGrants.get(refreshToken);
        if (grant == null) {
            return Optional.empty();
        }
        // 原子移除：并发刷新时只有一个线程能移除成功
        if (!refreshGrants.remove(refreshToken, grant)) {
            log.info("concurrent refresh lost race refresh={}", Masking.prefix(refreshToken));
            return Optional.empty();
        }
        if (!grant.expiresAt().isAfter(Instant.now(clock))) {
            log.info("refresh token expired refresh={}", Masking.prefix(refreshToken));
            return Optional.empty();
        }
        TokenPair pair = issue(grant.username());
        log.info("token refreshed user={} oldRefresh={}", grant.username(), Masking.prefix(refreshToken));
        return Optional.of(pair);
    }

    public void revoke(String accessToken) {
        validate(accessToken).ifPresentOrElse(
                vt -> {
                    accessGrants.remove(vt.jti());
                    log.info("access token revoked user={} jti={}", vt.username(), vt.jti());
                },
                () -> revokeByJtiOnly(accessToken));
    }

    public void revokeAllForUser(String username) {
        accessGrants.values().removeIf(g -> g.username().equals(username));
        refreshGrants.values().removeIf(g -> g.username().equals(username));
        log.info("all tokens revoked user={}", username);
    }

    /** 令牌已过期导致 validate 失败时，仍按载荷中的 jti 撤销（签名合法前提下）。 */
    private void revokeByJtiOnly(String accessToken) {
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) {
                return;
            }
            String signed = parts[0] + "." + parts[1];
            if (!MessageDigest.isEqual(sign(signed), B64D.decode(parts[2]))) {
                return;
            }
            JsonNode payload = mapper.readTree(B64D.decode(parts[1]));
            accessGrants.remove(payload.get("jti").asText());
        } catch (RuntimeException | java.io.IOException ignored) {
            // 无法解析的令牌无需撤销
        }
    }

    private String buildAccessToken(String username, String jti, Instant iat, Instant exp) {
        ObjectNode header = mapper.createObjectNode().put("alg", "HS256").put("typ", "JWT");
        ObjectNode payload = mapper.createObjectNode()
                .put("sub", username)
                .put("jti", jti)
                .put("iat", iat.getEpochSecond())
                .put("exp", exp.getEpochSecond());
        String signed = B64.encodeToString(header.toString().getBytes(StandardCharsets.UTF_8))
                + "." + B64.encodeToString(payload.toString().getBytes(StandardCharsets.UTF_8));
        return signed + "." + B64.encodeToString(sign(signed));
    }

    private byte[] sign(String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    private String newOpaque() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return B64.encodeToString(bytes);
    }
}
