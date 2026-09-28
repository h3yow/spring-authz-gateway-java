package com.github.h3yow.springauthzgatewayjava.auth;

import com.github.h3yow.springauthzgatewayjava.util.Masking;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 会话签发、滑动续期与撤销。
 *
 * <p>注册表项为终态机：{@code ACTIVE -> EXPIRED / REVOKED}。撤销通过
 * {@code compute} 原子地把条目转为 REVOKED 墓碑（而不是直接删除），续期通过
 * {@code computeIfPresent} 原子替换为顺延后的新记录——撤销与续期竞争时，
 * 已撤销的会话不会被续期"复活"，过期会话也不会因续期重新可用。
 *
 * <p>墓碑语义保证同一凭据的拒绝原因在生命周期内稳定不漂移：过期会话首次判定后
 * 转为 EXPIRED 墓碑，此后无论请求多少次都返回 EXPIRED；撤销会话转为 REVOKED
 * 墓碑，此后一直表现为"未知/已撤销"（与从未存在对外不可区分）。已经是 EXPIRED
 * 终态的凭据即使再被撤销，仍保持 EXPIRED，拒绝原因不翻转。墓碑在
 * {@code absoluteExpiresAt + sessionTtl} 之后才被惰性清理，覆盖完整判定窗口。
 *
 * <p>滑动续期语义：每次使用刷新 {@code lastUsedAt}；当剩余有效期不足
 * 空闲阈值（{@code auth.session-ttl}）的一半时，{@code expiresAt} 顺延为
 * {@code now + sessionTtl}，但永不超过绝对上限
 * {@code absoluteExpiresAt = createdAt + auth.session-max-lifetime}。
 */
@Component
public class SessionService {

    private static final Logger log = LoggerFactory.getLogger(SessionService.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    /** 会话判定结果：有效 / 已过期 / 未知或已撤销（二者对外不可区分）。 */
    public enum SessionStatus { VALID, EXPIRED, UNKNOWN }

    /** 判定结果快照：状态 + 有效时的记录。 */
    public record Evaluation(SessionStatus status, SessionRecord record) {}

    /** 续期结果：当前记录 + 本次是否真正顺延了过期时间。 */
    public record TouchResult(SessionRecord record, boolean renewed) {}

    /** 注册表内部状态：有效，或两类终态墓碑。 */
    private enum State { ACTIVE, EXPIRED, REVOKED }

    /** 注册表条目：终态机，一旦进入 EXPIRED/REVOKED 不可再变更。 */
    private record Entry(SessionRecord record, State state) {
        boolean terminal() {
            return state != State.ACTIVE;
        }
    }

    private final AuthProperties properties;
    private final Clock clock;
    private final ConcurrentHashMap<String, Entry> sessions = new ConcurrentHashMap<>();

    @org.springframework.beans.factory.annotation.Autowired
    public SessionService(AuthProperties properties) {
        this(properties, Clock.systemUTC());
    }

    SessionService(AuthProperties properties, Clock clock) {
        this.properties = properties;
        this.clock = clock;
    }

    public SessionRecord create(String username, Set<Role> roles) {
        return create(username, roles, "unknown");
    }

    public SessionRecord create(String username, Set<Role> roles, String client) {
        Instant now = clock.instant();
        SessionRecord record = new SessionRecord(
                newToken(), newToken(), username, Set.copyOf(roles), newToken(),
                client == null ? "unknown" : client,
                now, now, now.plus(properties.getSessionTtl()),
                now.plus(properties.getSessionMaxLifetime()));
        sessions.put(record.sessionId(), new Entry(record, State.ACTIVE));
        log.info("session created user={} session={} credential={}", username,
                Masking.mask(record.sessionId()), Masking.mask(record.credentialId()));
        return record;
    }

    /** 查询有效会话；不存在、已撤销或已过期一律返回空。 */
    public Optional<SessionRecord> find(String sessionId) {
        Evaluation evaluation = evaluate(sessionId);
        return evaluation.status() == SessionStatus.VALID
                ? Optional.of(evaluation.record()) : Optional.empty();
    }

    /**
     * 区分"有效 / 已过期 / 未知或已撤销"的判定，供认证过滤器给出可区分的拒绝原因。
     * 终态在首次判定时确定并落为墓碑：同一凭据重复请求得到的状态稳定不漂移。
     */
    public Evaluation evaluate(String sessionId) {
        if (sessionId == null) {
            return new Evaluation(SessionStatus.UNKNOWN, null);
        }
        Instant now = clock.instant();
        Evaluation[] answer = new Evaluation[1];
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (stale(current, now)) {
                answer[0] = new Evaluation(SessionStatus.UNKNOWN, null);
                return null; // 超出保留窗口的墓碑删除
            }
            if (current.terminal()) {
                answer[0] = new Evaluation(
                        current.state() == State.EXPIRED
                                ? SessionStatus.EXPIRED : SessionStatus.UNKNOWN, null);
                return current; // 终态不可变更
            }
            if (current.record().expired(now)) {
                answer[0] = new Evaluation(SessionStatus.EXPIRED, null);
                return new Entry(current.record(), State.EXPIRED); // 首次过期落墓碑
            }
            answer[0] = new Evaluation(SessionStatus.VALID, current.record());
            return current;
        });
        return answer[0] != null ? answer[0] : new Evaluation(SessionStatus.UNKNOWN, null);
    }

    /**
     * 滑动续期：原子地更新最近使用时间，并在剩余有效期过半后顺延过期时间
     * （不超过绝对上限）。已撤销或已过期的会话（含终态墓碑）不会被续期复活。
     *
     * @return 会话仍处于 ACTIVE 且有效时返回续期结果，否则返回空
     */
    public Optional<TouchResult> touch(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        Instant now = clock.instant();
        TouchResult[] result = new TouchResult[1];
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (stale(current, now)) {
                return null;
            }
            if (current.state() != State.ACTIVE) {
                return current; // 终态墓碑保持不变，绝不复活
            }
            SessionRecord r = current.record();
            if (r.expired(now)) {
                return new Entry(r, State.EXPIRED); // 过期落墓碑，绝不复活
            }
            boolean renewable = r.expiresAt().isBefore(r.absoluteExpiresAt())
                    && now.plus(properties.getSessionTtl().dividedBy(2)).isAfter(r.expiresAt());
            Instant newExpiry = renewable
                    ? min(now.plus(properties.getSessionTtl()), r.absoluteExpiresAt())
                    : r.expiresAt();
            boolean renewed = newExpiry.isAfter(r.expiresAt());
            result[0] = new TouchResult(new SessionRecord(
                    r.sessionId(), r.credentialId(), r.username(),
                    r.roles(), r.csrfToken(), r.client(),
                    r.createdAt(), now, newExpiry, r.absoluteExpiresAt()), renewed);
            return new Entry(result[0].record(), State.ACTIVE);
        });
        return Optional.ofNullable(result[0]);
    }

    /** 撤销单个会话，立即生效；重复撤销幂等，终态统一收敛（EXPIRED 不翻转为 REVOKED）。 */
    public void revoke(String sessionId) {
        if (sessionId == null) {
            return;
        }
        boolean[] wasActive = {false};
        sessions.computeIfPresent(sessionId, (id, current) -> {
            if (stale(current, clock.instant())) {
                return null;
            }
            if (current.state() == State.ACTIVE) {
                wasActive[0] = true;
                return new Entry(current.record(), State.REVOKED);
            }
            return current; // EXPIRED 保持 EXPIRED，REVOKED 保持 REVOKED
        });
        if (wasActive[0]) {
            log.info("session revoked session={}", Masking.mask(sessionId));
        }
    }

    /** 按公开凭据标识撤销：仅当凭据属于该用户且仍有效时生效，返回是否命中。 */
    public boolean revokeByCredentialId(String username, String credentialId) {
        if (credentialId == null) {
            return false;
        }
        for (Entry e : List.copyOf(sessions.values())) {
            SessionRecord s = e.record();
            if (!s.credentialId().equals(credentialId) || !s.username().equals(username)) {
                continue;
            }
            boolean[] hit = {false};
            sessions.computeIfPresent(s.sessionId(), (id, current) -> {
                if (stale(current, clock.instant())) {
                    return null;
                }
                if (current.state() == State.ACTIVE) {
                    hit[0] = true;
                    return new Entry(current.record(), State.REVOKED);
                }
                return current;
            });
            if (hit[0]) {
                log.info("session revoked by credential user={} credential={}",
                        username, Masking.mask(credentialId));
            }
            return hit[0];
        }
        return false;
    }

    /** 撤销某用户的全部 ACTIVE 会话（如登出所有设备、口令变更），终态墓碑保证拒绝原因稳定。 */
    public void revokeAllForUser(String username) {
        int[] revoked = {0};
        sessions.replaceAll((id, current) -> {
            if (current.record().username().equals(username) && current.state() == State.ACTIVE) {
                revoked[0]++;
                return new Entry(current.record(), State.REVOKED);
            }
            return current;
        });
        if (revoked[0] > 0) {
            log.info("all sessions revoked user={} count={}", username, revoked[0]);
        }
    }

    /** 撤销某用户除指定会话外的全部 ACTIVE 会话（"撤销其他全部凭据"）。 */
    public void revokeAllForUserExcept(String username, String keepSessionId) {
        int[] revoked = {0};
        sessions.replaceAll((id, current) -> {
            if (current.record().username().equals(username)
                    && !current.record().sessionId().equals(keepSessionId)
                    && current.state() == State.ACTIVE) {
                revoked[0]++;
                return new Entry(current.record(), State.REVOKED);
            }
            return current;
        });
        if (revoked[0] > 0) {
            log.info("other sessions revoked user={} keep={} count={}",
                    username, Masking.mask(keepSessionId), revoked[0]);
        }
    }

    /** 列出某用户当前仍有效的会话（过期会话顺带落为 EXPIRED 墓碑）。 */
    public List<SessionRecord> listForUser(String username) {
        Instant now = clock.instant();
        return sessions.values().stream()
                .filter(e -> e.record().username().equals(username))
                .filter(e -> e.state() == State.ACTIVE)
                .filter(e -> {
                    if (!e.record().expired(now)) {
                        return true;
                    }
                    // 原子落墓碑：只有 CAS 成功把 ACTIVE 转成 EXPIRED 的这一路判定为失效
                    Entry replaced = sessions.compute(e.record().sessionId(), (id, current) ->
                            current != null && current.state() == State.ACTIVE && current.record().expired(now)
                                    ? new Entry(current.record(), State.EXPIRED) : current);
                    return replaced.state() == State.ACTIVE;
                })
                .map(Entry::record)
                .toList();
    }

    /**
     * 墓碑是否超过保留窗口；超过则可从注册表删除。
     * 保留到 {@code max(空闲失效时间, 绝对上限) + 一个空闲 TTL}：既覆盖空闲过期场景
     * （expiresAt 较早），也覆盖到达绝对上限的场景（absoluteExpiresAt 为最后失效点），
     * 清理之前同一凭据的拒绝原因保持稳定。
     */
    private boolean stale(Entry entry, Instant now) {
        SessionRecord r = entry.record();
        Instant retainUntil = (r.expiresAt().isAfter(r.absoluteExpiresAt())
                ? r.expiresAt() : r.absoluteExpiresAt())
                .plus(properties.getSessionTtl());
        return entry.terminal() && !now.isBefore(retainUntil);
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }

    private static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
