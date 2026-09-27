package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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
 *   <li>按单个访问令牌撤销：元数据注册表原子翻转为墓碑（{@code revoked=true}），
 *       立即生效且绝不复活；墓碑同时支撑"已撤销/已过期/不被认可"的稳定区分；</li>
 *   <li>刷新令牌单次使用：jti 注册表原子移除，并发刷新只有一个成功，绝不重复签发。</li>
 * </ul>
 *
 * <p>访问令牌元数据（签发来源、最近使用时间）保存在服务端注册表中，
 * 仅用于自助管理视图与撤销判定，不出现在令牌原文里。
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

    /** 访问令牌服务端元数据（不可变；撤销/使用通过整体替换完成，无半更新态）。 */
    private record TokenMeta(String jti, String username, String clientKey,
                             Instant issuedAt, Instant lastUsedAt, Instant expiresAt,
                             String refreshJti, boolean revoked) {
        TokenMeta asUsed(Instant now) {
            return new TokenMeta(jti, username, clientKey, issuedAt, now, expiresAt, refreshJti, revoked);
        }
        TokenMeta asRevoked() {
            return new TokenMeta(jti, username, clientKey, issuedAt, lastUsedAt, expiresAt, refreshJti, true);
        }
    }

    private final AuthProperties properties;
    private final Clock clock;
    private final byte[] secret;

    /** 每个用户的撤销纪元：早于此时间签发的令牌一律拒绝。 */
    private final ConcurrentHashMap<String, Instant> revocationEpoch = new ConcurrentHashMap<>();
    /** 有效刷新令牌注册表：jti -> 用户名。 */
    private final ConcurrentHashMap<String, String> refreshRegistry = new ConcurrentHashMap<>();
    /** 访问令牌元数据注册表：jti -> 元数据（含撤销墓碑）。 */
    private final ConcurrentHashMap<String, TokenMeta> accessRegistry = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public TokenService(AuthProperties properties) {
        this(properties, Clock.systemUTC(), randomSecret());
    }

    /** 测试/嵌入用：可注入时钟与密钥。 */
    public TokenService(AuthProperties properties, Clock clock, byte[] secret) {
        this.properties = properties;
        this.clock = clock;
        this.secret = secret;
    }

    private static byte[] randomSecret() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /** 兼容入口：未提供客户端来源时以 unknown 签发。 */
    public TokenPair issue(String username, Set<Role> roles) {
        return issue(username, roles, "unknown");
    }

    public TokenPair issue(String username, Set<Role> roles, String clientKey) {
        Instant now = clock.instant();
        String accessJti = newJti();
        String access = encode(new Payload(username, roles, accessJti, TYPE_ACCESS,
                now, now.plus(properties.getAccessTokenTtl())));
        String refreshJti = newJti();
        String refresh = encode(new Payload(username, roles, refreshJti, TYPE_REFRESH,
                now, now.plus(properties.getRefreshTokenTtl())));
        refreshRegistry.put(refreshJti, username);
        accessRegistry.put(accessJti, new TokenMeta(accessJti, username,
                clientKey == null ? "unknown" : clientKey,
                now, now, now.plus(properties.getAccessTokenTtl()), refreshJti, false));
        log.info("token pair issued user={} accessJti={} refreshJti={} client={}",
                username, Masking.mask(accessJti), Masking.mask(refreshJti), clientKey);
        return new TokenPair(access, refresh);
    }

    /** 校验访问令牌：签名、有效期、类型、撤销纪元、单令牌墓碑全部通过才接受；接受即记录一次使用。 */
    public Optional<TokenSubject> verifyAccessToken(String token) {
        Optional<Payload> parsed = decode(token)
                .filter(p -> TYPE_ACCESS.equals(p.type()))
                .filter(this::notExpired)
                .filter(this::notRevokedByEpoch);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        Payload p = parsed.get();
        // 原子校验并记录使用：墓碑不会被复活
        TokenMeta meta = accessRegistry.computeIfPresent(p.jti(), (jti, cur) ->
                cur.revoked() ? cur : cur.asUsed(clock.instant()));
        if (meta == null || meta.revoked()) {
            return Optional.empty();
        }
        return Optional.of(new TokenSubject(p.sub(), p.roles()));
    }

    /** 判定访问令牌的生命周期状态，稳定区分 已撤销 / 已过期 / 不被认可（含伪造与旧凭据）。 */
    public CredentialState stateOfAccessToken(String token) {
        Optional<Payload> parsed = decode(token).filter(p -> TYPE_ACCESS.equals(p.type()));
        if (parsed.isEmpty()) {
            return CredentialState.UNKNOWN;
        }
        Payload p = parsed.get();
        TokenMeta meta = accessRegistry.get(p.jti());
        if (meta == null) {
            return CredentialState.UNKNOWN; // 服务端不再认可（如重启前的旧凭据）
        }
        if (meta.revoked() || !notRevokedByEpoch(p)) {
            return CredentialState.REVOKED;
        }
        if (!notExpired(p)) {
            return CredentialState.EXPIRED;
        }
        return CredentialState.VALID;
    }

    /** 并发安全刷新：刷新令牌单次使用，jti 从注册表原子移除，并发下只有一个成功。 */
    public Optional<TokenPair> refresh(String refreshToken) {
        return refresh(refreshToken, "unknown");
    }

    public Optional<TokenPair> refresh(String refreshToken, String clientKey) {
        Optional<Payload> parsed = decode(refreshToken)
                .filter(p -> TYPE_REFRESH.equals(p.type()))
                .filter(this::notExpired)
                .filter(this::notRevokedByEpoch);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        Payload p = parsed.get();
        // 原子移除：并发下只有一个线程能移除成功
        if (!refreshRegistry.remove(p.jti(), p.sub())) {
            log.info("refresh token already used or revoked jti={}", Masking.mask(p.jti()));
            return Optional.empty();
        }
        return Optional.of(issue(p.sub(), p.roles(), clientKey));
    }

    /** 撤销某用户的全部令牌：提升撤销纪元、注销全部刷新令牌、全部访问令牌打墓碑，立即生效。 */
    public void revokeAllForUser(String username) {
        revocationEpoch.put(username, clock.instant());
        refreshRegistry.values().removeIf(username::equals);
        accessRegistry.values().forEach(meta -> {
            if (meta.username().equals(username)) {
                accessRegistry.computeIfPresent(meta.jti(), (jti, cur) -> cur.asRevoked());
            }
        });
        log.info("all tokens revoked user={}", username);
    }

    /**
     * 撤销某用户除指定访问令牌（jti）之外的全部令牌。
     * 保留指定访问令牌及其同对的刷新令牌（保持当前客户端可用），其余一律撤销。
     * 墓碑不会被复活，重复调用幂等。
     *
     * @return 被撤销的（此前有效的）访问令牌数量
     */
    public int revokeAllForUserExcept(String username, String keepAccessJti) {
        final int[] changed = {0};
        String keepRefreshJti = null;
        for (Map.Entry<String, TokenMeta> e : accessRegistry.entrySet()) {
            TokenMeta meta = e.getValue();
            if (!meta.username().equals(username)) {
                continue;
            }
            if (meta.jti().equals(keepAccessJti)) {
                keepRefreshJti = meta.refreshJti();
                continue;
            }
            accessRegistry.compute(e.getKey(), (jti, cur) -> {
                if (cur == null || cur.revoked() || !clock.instant().isBefore(cur.expiresAt())) {
                    return cur; // 过期凭据不计入撤销数，保持 EXPIRED 判定
                }
                changed[0]++;
                return cur.asRevoked();
            });
        }
        // 注销该用户其余刷新令牌（保留与幸存访问令牌同对的那一个）
        final String keepRefresh = keepRefreshJti;
        refreshRegistry.entrySet().removeIf(en ->
                en.getValue().equals(username) && !en.getKey().equals(keepRefresh));
        log.info("tokens revoked user={} keepAccessJti={} count={}",
                username, Masking.mask(keepAccessJti), changed[0]);
        return changed[0];
    }

    /** 撤销单个访问令牌（按 jti），立即生效；对墓碑/不存在条目幂等，绝不复活。 */
    public boolean revokeAccessToken(String jti) {
        if (jti == null) {
            return false;
        }
        final boolean[] changed = {false};
        accessRegistry.computeIfPresent(jti, (id, cur) -> {
            if (!cur.revoked() && clock.instant().isBefore(cur.expiresAt())) {
                changed[0] = true;
                log.info("access token revoked jti={}", Masking.mask(jti));
                return cur.asRevoked();
            }
            return cur; // 已撤销/已过期：幂等 no-op
        });
        return changed[0];
    }

    /** 撤销单个刷新令牌（如登出）。 */
    public void revokeRefreshToken(String refreshToken) {
        decode(refreshToken).filter(p -> TYPE_REFRESH.equals(p.type()))
                .ifPresent(p -> refreshRegistry.remove(p.jti()));
    }

    /** 用户名下当前仍然有效的访问令牌视图（仅元数据，不含令牌原文）。 */
    public List<CredentialInfo> activeInfos(String username) {
        Instant now = clock.instant();
        List<CredentialInfo> result = new ArrayList<>();
        for (TokenMeta m : accessRegistry.values()) {
            if (m.username().equals(username) && !m.revoked() && now.isBefore(m.expiresAt())) {
                result.add(new CredentialInfo(m.jti(), CredentialKind.ACCESS_TOKEN,
                        m.clientKey(), m.issuedAt(), m.lastUsedAt(), m.expiresAt()));
            }
        }
        return result;
    }

    /** 访问令牌 jti 是否属于指定用户（供撤销前归属校验，避免越权撤销他人凭据）。 */
    public boolean accessTokenBelongsTo(String jti, String username) {
        TokenMeta meta = accessRegistry.get(jti);
        return meta != null && meta.username().equals(username);
    }

    /** 从令牌（验签通过后）提取 jti；畸形/伪造令牌返回 null。jti 为随机标识，非令牌原文。 */
    public String jtiOf(String token) {
        return decode(token).map(Payload::jti).orElse(null);
    }

    private boolean notExpired(Payload p) {
        return clock.instant().isBefore(p.exp());
    }

    private boolean notRevokedByEpoch(Payload p) {
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
