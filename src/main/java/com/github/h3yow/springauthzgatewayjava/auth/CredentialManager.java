package com.github.h3yow.springauthzgatewayjava.auth;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 活跃凭据自助管理门面：聚合会话与刷新令牌两类凭据的列举与撤销。
 *
 * <p>列举结果只含公开元数据（公开凭据标识、种类、客户端、签发/最近使用/失效时间），
 * 不含任何凭据本体。撤销立即生效；并发撤销（单个与全部、重复撤销）最终收敛：
 * 注册表原子删除 + 拒绝名单，已撤销凭据不会复活，重复撤销是幂等 no-op。
 */
@Service
public class CredentialManager {

    private static final Logger log = LoggerFactory.getLogger(CredentialManager.class);

    public static final String KIND_SESSION = "SESSION";
    public static final String KIND_REFRESH_TOKEN = "REFRESH_TOKEN";

    /** 凭据公开视图：绝不包含凭据本体（sessionId、jti、令牌串）。 */
    public record CredentialView(String credentialId, String kind, String client,
                                 Instant issuedAt, Instant lastUsedAt, Instant expiresAt) {}

    /** 当前请求所用的凭据：会话（sessionId）或访问令牌所属凭据（credentialId）。 */
    public record CurrentCredential(String kind, String sessionId, String credentialId) {

        public static CurrentCredential session(String sessionId) {
            return new CurrentCredential(KIND_SESSION, sessionId, null);
        }

        public static CurrentCredential token(String credentialId) {
            return new CurrentCredential(KIND_REFRESH_TOKEN, null, credentialId);
        }
    }

    private final SessionService sessionService;
    private final TokenService tokenService;

    public CredentialManager(SessionService sessionService, TokenService tokenService) {
        this.sessionService = sessionService;
        this.tokenService = tokenService;
    }

    /** 列出用户当前仍有效的全部凭据（会话 + 刷新令牌），按签发时间排序。 */
    public List<CredentialView> list(String username) {
        List<CredentialView> views = new ArrayList<>();
        for (SessionRecord s : sessionService.listForUser(username)) {
            views.add(new CredentialView(s.credentialId(), KIND_SESSION, s.client(),
                    s.createdAt(), s.lastUsedAt(), s.expiresAt()));
        }
        for (TokenService.RefreshMeta m : tokenService.listRefreshForUser(username)) {
            views.add(new CredentialView(m.credentialId(), KIND_REFRESH_TOKEN, m.client(),
                    m.issuedAt(), m.lastUsedAt(), m.expiresAt()));
        }
        views.sort(Comparator.comparing(CredentialView::issuedAt));
        return views;
    }

    /**
     * 撤销单个凭据（按公开凭据标识），仅当凭据属于该用户时生效。
     * 立即失效，不影响该用户其他凭据；重复撤销幂等。
     *
     * @return 是否命中并撤销了一个有效凭据
     */
    public boolean revokeOne(String username, String credentialId) {
        boolean sessionHit = sessionService.revokeByCredentialId(username, credentialId);
        boolean tokenHit = tokenService.revokeByCredentialId(username, credentialId);
        log.info("credential revoke-one user={} hit={}", username, sessionHit || tokenHit);
        return sessionHit || tokenHit;
    }

    /**
     * 撤销该用户除当前凭据外的全部凭据，立即生效。
     * 当前凭据为会话时：保留该会话，撤销其他会话与全部令牌凭据；
     * 当前凭据为访问令牌时：保留其所属令牌凭据，撤销全部会话与其他令牌凭据。
     */
    public void revokeAllExcept(String username, CurrentCredential current) {
        if (current != null && KIND_SESSION.equals(current.kind()) && current.sessionId() != null) {
            sessionService.revokeAllForUserExcept(username, current.sessionId());
            tokenService.revokeAllForUserExcept(username, null);
        } else if (current != null && current.credentialId() != null) {
            sessionService.revokeAllForUser(username);
            tokenService.revokeAllForUserExcept(username, current.credentialId());
        } else {
            sessionService.revokeAllForUser(username);
            tokenService.revokeAllForUserExcept(username, null);
        }
        log.info("credential revoke-others user={} keepKind={}", username,
                current != null ? current.kind() : "none");
    }
}
