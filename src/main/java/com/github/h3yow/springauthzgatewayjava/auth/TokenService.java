package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
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
 * payload 为 {@code sub|roles|jti|type|iat|exp|cid} 的分号分隔串（本地子系统，无需通用 JWT 库）。
 * {@code cid} 是公开凭据标识：一次登录签发的令牌对共享一个 cid，刷新旋转时保持不变，
 * 用于凭据自助管理（列举/撤销），与凭据本体（jti、令牌串）分离。
 *
 * <p>撤销语义：
 * <ul>
 *   <li>按用户撤销：提升该用户的撤销纪元（epoch），纪元之前签发的令牌一律拒绝，立即生效；</li>
 *   <li>按凭据撤销：刷新令牌从注册表原子移除，该凭据派生的访问令牌进入拒绝名单，立即生效；</li>
 *   <li>刷新令牌单次使用：jti 注册表原子移除，并发刷新只有一个成功，绝不重复签发；</li>
 *   <li>访问令牌短有效期 + 纪元/拒绝名单校验，撤销后不再被任何入口接受。</li>
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

    /** 访问令牌判定结果：有效 / 已过期 / 已撤销或无效（对外不再细分，避免泄露）。 */
    public enum TokenStatus { VALID, EXPIRED, INVALID }

    /** 刷新令牌凭据的公开元数据（不含任何凭据本体）。 */
    public record RefreshMeta(String credentialId, String username, String client,
                              Instant issuedAt, Instant lastUsedAt, Instant expiresAt) {}

    private record Payload(String sub, Set<Role> roles, String jti, String type,
                           Instant iat, Instant exp, String cid) {}

    /** 访问令牌登记元数据，用于按凭据撤销时即时失效。 */
    private record AccessMeta(String username, String cid, Instant exp) {}

    private final AuthProperties properties;
    private final Clock clock;
    private final byte[] secret;

    /** 每个用户的撤销纪元：早于此时间签发的令牌一律拒绝。 */
    private final ConcurrentHashMap<String, Instant> revocationEpoch = new ConcurrentHashMap<>();
    /** 有效刷新令牌注册表：jti -> 凭据元数据。 */
    private final ConcurrentHashMap<String, RefreshMeta> refreshRegistry = new ConcurrentHashMap<>();
    /** 访问令牌登记：jti -> 元数据（过期后惰性清理）。 */
    private final ConcurrentHashMap<String, AccessMeta> accessRegistry = new ConcurrentHashMap<>();
    /** 已撤销访问令牌拒绝名单：jti -> 原过期时间（过期后惰性清理）。 */
    private final ConcurrentHashMap<String, Instant> revokedAccessJti = new ConcurrentHashMap<>();

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
        return issue(username, roles, "unknown");
    }

    /** 新登录签发：生成新的公开凭据标识。 */
    public TokenPair issue(String username, Set<Role> roles, String client) {
        return issueInternal(username, roles, client == null ? "unknown" : client, newJti(), null);
    }

    private TokenPair issueInternal(String username, Set<Role> roles, String client,
                                    String credentialId, RefreshMeta previous) {
        Instant now = clock.instant();
        purgeExpired(now);
        String accessJti = newJti();
        Instant accessExp = now.plus(properties.getAccessTokenTtl());
        String access = encode(new Payload(username, roles, accessJti, TYPE_ACCESS,
                now, accessExp, credentialId));
        String refreshJti = newJti();
        Instant refreshExp = now.plus(properties.getRefreshTokenTtl());
        String refresh = encode(new Payload(username, roles, refreshJti, TYPE_REFRESH,
                now, refreshExp, credentialId));
        // 旋转时保留原凭据的签发时间与客户端，最近使用时间更新为当前
        Instant issuedAt = previous != null ? previous.issuedAt() : now;
        refreshRegistry.put(refreshJti, new RefreshMeta(credentialId, username, client,
                issuedAt, now, refreshExp));
        accessRegistry.put(accessJti, new AccessMeta(username, credentialId, accessExp));
        log.info("token pair issued user={} credential={} refreshJti={}", username,
                Masking.mask(credentialId), Masking.mask(refreshJti));
        return new TokenPair(access, refresh);
    }

    /** 校验访问令牌：签名、有效期、类型、撤销纪元、拒绝名单全部通过才接受。 */
    public Optional<TokenSubject> verifyAccessToken(String token) {
        return decode(token)
                .filter(p -> TYPE_ACCESS.equals(p.type()))
                .filter(this::notExpired)
                .filter(this::notRevoked)
                .filter(p -> !revokedAccessJti.containsKey(p.jti()))
                .map(p -> new TokenSubject(p.sub(), p.roles()));
    }

    /** 区分"有效 / 已过期 / 已撤销或无效"的判定，供认证过滤器给出可区分的拒绝原因。 */
    public TokenStatus evaluateAccessToken(String token) {
        Optional<Payload> parsed = decode(token).filter(p -> TYPE_ACCESS.equals(p.type()));
        if (parsed.isEmpty()) {
            return TokenStatus.INVALID;
        }
        Payload p = parsed.get();
        if (!notExpired(p)) {
            return TokenStatus.EXPIRED;
        }
        if (!notRevoked(p) || revokedAccessJti.containsKey(p.jti())) {
            return TokenStatus.INVALID;
        }
        return TokenStatus.VALID;
    }

    /**
     * 并发安全刷新：刷新令牌单次使用，jti 从注册表原子移除，
     * 同一刷新令牌的并发请求只有一个能成功，其余一律拒绝，绝不重复签发。
     * 旋转后凭据标识（cid）与最初签发时间保持不变，最近使用时间更新。
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
        RefreshMeta meta = refreshRegistry.remove(p.jti());
        if (meta == null || !meta.username().equals(p.sub())) {
            log.info("refresh token already used or revoked jti={}", Masking.mask(p.jti()));
            return Optional.empty();
        }
        return Optional.of(issueInternal(p.sub(), p.roles(), meta.client(), p.cid(), meta));
    }

    /** 撤销某用户的全部令牌：提升撤销纪元并注销其全部刷新令牌，立即生效。 */
    public void revokeAllForUser(String username) {
        revocationEpoch.put(username, clock.instant());
        refreshRegistry.values().removeIf(m -> m.username().equals(username));
        accessRegistry.values().removeIf(m -> m.username().equals(username));
        log.info("all tokens revoked user={}", username);
    }

    /**
     * 撤销某用户除指定凭据外的全部令牌（"撤销其他全部凭据"）：
     * 其余刷新令牌从注册表移除，其余凭据派生的访问令牌进入拒绝名单，立即生效；
     * 已撤销/已过期的令牌不会因此恢复。
     *
     * @param keepCredentialId 要保留的公开凭据标识；为 null 时撤销该用户全部令牌
     */
    public void revokeAllForUserExcept(String username, String keepCredentialId) {
        Instant now = clock.instant();
        refreshRegistry.values().removeIf(m -> m.username().equals(username)
                && !m.credentialId().equals(keepCredentialId));
        accessRegistry.forEach((jti, meta) -> {
            if (meta.username().equals(username) && !meta.cid().equals(keepCredentialId)) {
                revokedAccessJti.put(jti, meta.exp());
                accessRegistry.remove(jti, meta);
            }
        });
        purgeExpired(now);
        log.info("other tokens revoked user={} keep={}", username, Masking.mask(keepCredentialId));
    }

    /** 按公开凭据标识撤销：仅当凭据属于该用户时生效；其派生访问令牌一并即时失效。 */
    public boolean revokeByCredentialId(String username, String credentialId) {
        if (credentialId == null) {
            return false;
        }
        boolean[] hit = {false};
        refreshRegistry.values().removeIf(m -> {
            boolean match = m.credentialId().equals(credentialId) && m.username().equals(username);
            hit[0] |= match;
            return match;
        });
        accessRegistry.forEach((jti, meta) -> {
            if (meta.cid().equals(credentialId) && meta.username().equals(username)) {
                revokedAccessJti.put(jti, meta.exp());
                accessRegistry.remove(jti, meta);
            }
        });
        if (hit[0]) {
            log.info("refresh credential revoked user={} credential={}",
                    username, Masking.mask(credentialId));
        }
        return hit[0];
    }

    /** 撤销单个刷新令牌（如登出）。 */
    public void revokeRefreshToken(String refreshToken) {
        decode(refreshToken).filter(p -> TYPE_REFRESH.equals(p.type()))
                .ifPresent(p -> refreshRegistry.remove(p.jti()));
    }

    /** 提取访问令牌的公开凭据标识（用于"撤销其他全部凭据"时识别当前凭据）。 */
    public Optional<String> credentialIdOf(String accessToken) {
        return decode(accessToken)
                .filter(p -> TYPE_ACCESS.equals(p.type()))
                .map(Payload::cid);
    }

    /** 列出某用户当前仍有效的刷新令牌凭据元数据（过期条目顺带惰性剔除）。 */
    public List<RefreshMeta> listRefreshForUser(String username) {
        Instant now = clock.instant();
        purgeExpired(now);
        return refreshRegistry.values().stream()
                .filter(m -> m.username().equals(username))
                .toList();
    }

    /** 惰性清理过期条目，避免注册表无界增长。 */
    private void purgeExpired(Instant now) {
        refreshRegistry.values().removeIf(m -> !now.isBefore(m.expiresAt()));
        accessRegistry.values().removeIf(m -> !now.isBefore(m.exp()));
        revokedAccessJti.values().removeIf(exp -> !now.isBefore(exp));
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
                String.valueOf(p.iat().toEpochMilli()), String.valueOf(p.exp().toEpochMilli()), p.cid());
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
            if (f.length != 7) {
                return Optional.empty();
            }
            Set<Role> roles = f[1].isEmpty() ? Set.of()
                    : java.util.Arrays.stream(f[1].split(",")).map(Role::valueOf).collect(Collectors.toSet());
            return Optional.of(new Payload(f[0], roles, f[2], f[3],
                    Instant.ofEpochMilli(Long.parseLong(f[4])), Instant.ofEpochMilli(Long.parseLong(f[5])),
                    f[6]));
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
