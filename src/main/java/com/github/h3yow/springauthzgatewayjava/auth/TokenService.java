package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 无状态令牌（HMAC-SHA256 签名）签发、校验、刷新与撤销。
 *
 * <p>令牌格式：{@code v1.<base64url(payload)>.<base64url(signature)>}，
 * payload 为 {@code sub|roles|jti|type|iat|exp} 的分号分隔串（本地子系统，无需通用 JWT 库）。
 *
 * <p>撤销语义：
 * <ul>
 *   <li>按用户撤销：提升该用户的撤销纪元（epoch），纪元之前签发的令牌一律拒绝，立即生效；</li>
 *   <li>刷新令牌单次使用：jti 注册表原子移除，并发刷新只有一个成功，绝不重复签发；</li>
 *   <li>访问令牌短有效期 + 纪元校验，撤销后不再被任何入口接受。</li>
 * </ul>
 */
@Component
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final String VERSION = "v1";
    private static final String TYPE_ACCESS = "access";
    private static final String TYPE_REFRESH = "refresh";

    public record TokenPair(String accessToken, String refreshToken) {}
    public record TokenSubject(String username, Set<Role> roles) {}

    private record Payload(String sub, Set<Role> roles, String jti, String type, Instant iat, Instant exp) {}

    private final AuthProperties properties;
    private final Clock clock;
    private final byte[] secret;

    /** 每个用户的撤销纪元：早于此时间签发的令牌一律拒绝。 */
    private final ConcurrentHashMap<String, Instant> revocationEpoch = new ConcurrentHashMap<>();
    /** 有效刷新令牌注册表：jti -> 用户名。 */
    private final ConcurrentHashMap<String, String> refreshRegistry = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public TokenService(AuthProperties properties) {
        this(properties, Clock.systemUTC(), randomSecret());
    }

    TokenService(AuthProperties properties, Clock clock, byte[] secret) {
        this.properties = properties;
        this.clock = clock;
        this.secret = secret;
    }

    private static byte[] randomSecret() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    public TokenPair issue(String username, Set<Role> roles) {
        Instant now = clock.instant();
        String access = encode(new Payload(username, roles, newJti(), TYPE_ACCESS,
                now, now.plus(properties.getAccessTokenTtl())));
        String refreshJti = newJti();
        String refresh = encode(new Payload(username, roles, refreshJti, TYPE_REFRESH,
                now, now.plus(properties.getRefreshTokenTtl())));
        refreshRegistry.put(refreshJti, username);
        log.info("token pair issued user={} refreshJti={}", username, Masking.mask(refreshJti));
        return new TokenPair(access, refresh);
    }

    /** 校验访问令牌：签名、有效期、类型、撤销纪元全部通过才接受。 */
    public Optional<TokenSubject> verifyAccessToken(String token) {
        return decode(token)
                .filter(p -> TYPE_ACCESS.equals(p.type()))
                .filter(this::notExpired)
                .filter(this::notRevoked)
                .map(p -> new TokenSubject(p.sub(), p.roles()));
    }

    /**
     * 并发安全刷新：刷新令牌单次使用，jti 从注册表原子移除，
     * 同一刷新令牌的并发请求只有一个能成功，其余一律拒绝，绝不重复签发。
     */
    public Optional<TokenPair> refresh(String refreshToken) {
        Optional<Payload> parsed = decode(refreshToken)
                .filter(p -> TYPE_REFRESH.equals(p.type()))
                .filter(this::notExpired)
                .filter(this::notRevoked);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        Payload p = parsed.get();
        // 原子移除：并发下只有一个线程能移除成功
        if (!refreshRegistry.remove(p.jti(), p.sub())) {
            log.info("refresh token already used or revoked jti={}", Masking.mask(p.jti()));
            return Optional.empty();
        }
        return Optional.of(issue(p.sub(), p.roles()));
    }

    /** 撤销某用户的全部令牌：提升撤销纪元并注销其全部刷新令牌，立即生效。 */
    public void revokeAllForUser(String username) {
        revocationEpoch.put(username, clock.instant());
        refreshRegistry.values().removeIf(username::equals);
        log.info("all tokens revoked user={}", username);
    }

    /** 撤销单个刷新令牌（如登出）。 */
    public void revokeRefreshToken(String refreshToken) {
        decode(refreshToken).filter(p -> TYPE_REFRESH.equals(p.type()))
                .ifPresent(p -> refreshRegistry.remove(p.jti()));
    }

    private boolean notExpired(Payload p) {
        return clock.instant().isBefore(p.exp());
    }

    private boolean notRevoked(Payload p) {
        Instant epoch = revocationEpoch.get(p.sub());
        return epoch == null || !p.iat().isBefore(epoch);
    }

    // ---- 编解码 ----

    private String encode(Payload p) {
        String roles = p.roles().stream().map(Role::name).sorted().collect(Collectors.joining(","));
        String body = String.join("|", p.sub(), roles, p.jti(), p.type(),
                String.valueOf(p.iat().toEpochMilli()), String.valueOf(p.exp().toEpochMilli()));
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(body.getBytes(StandardCharsets.UTF_8));
        return VERSION + "." + payload + "." + sign(payload);
    }

    private Optional<Payload> decode(String token) {
        try {
            if (token == null) {
                return Optional.empty();
            }
            String[] parts = token.split("\\.");
            if (parts.length != 3 || !VERSION.equals(parts[0])) {
                return Optional.empty();
            }
            // 常量时间比较签名，防时序侧信道与伪造
            if (!MessageDigest.isEqual(sign(parts[1]).getBytes(StandardCharsets.UTF_8),
                    parts[2].getBytes(StandardCharsets.UTF_8))) {
                return Optional.empty();
            }
            String body = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String[] f = body.split("\\|", -1);
            if (f.length != 6) {
                return Optional.empty();
            }
            Set<Role> roles = f[1].isEmpty() ? Set.of()
                    : java.util.Arrays.stream(f[1].split(",")).map(Role::valueOf).collect(Collectors.toSet());
            return Optional.of(new Payload(f[0], roles, f[2], f[3],
                    Instant.ofEpochMilli(Long.parseLong(f[4])), Instant.ofEpochMilli(Long.parseLong(f[5]))));
        } catch (RuntimeException e) {
            return Optional.empty(); // 任何畸形令牌一律拒绝
        }
    }

    private String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    private static String newJti() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
