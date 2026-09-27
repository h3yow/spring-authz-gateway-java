package com.github.h3yow.springauthzgatewayjava.auth;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 活跃凭据自助管理：聚合用户名下仍然有效的会话与访问令牌，
 * 支持撤销单个凭据与一键撤销除当前凭据外的全部凭据。
 *
 * <p>本服务只编排 {@link SessionService} 与 {@link TokenService}，不保存额外状态；
 * 会话句柄与令牌 jti 均为不可逆随机值，凭据原文不离开各自服务。
 * 撤销前做归属校验，用户只能操作自己名下的凭据。
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final SessionService sessionService;
    private final TokenService tokenService;

    public CredentialService(SessionService sessionService, TokenService tokenService) {
        this.sessionService = sessionService;
        this.tokenService = tokenService;
    }

    /** 列出用户名下当前仍然有效的全部凭据（仅元数据，不含原文），按签发时间升序。 */
    public List<CredentialInfo> listActive(String username) {
        List<CredentialInfo> all = new java.util.ArrayList<>();
        all.addAll(sessionService.activeInfos(username));
        all.addAll(tokenService.activeInfos(username));
        all.sort(Comparator.comparing(CredentialInfo::issuedAt));
        return List.copyOf(all);
    }

    /**
     * 撤销用户名下的单个凭据；幂等：重复撤销返回 false 且不改变结果。
     * 不属于该用户的凭据一律拒绝（返回 false），避免越权撤销。
     *
     * @return true 表示该凭据此前有效、本次被撤销；false 表示不存在、不归属或此前已撤销/过期
     */
    public boolean revokeCredential(String username, String credentialId) {
        if (username == null || credentialId == null) {
            return false;
        }
        Optional<SessionRecord> session = sessionService.findByCredentialId(credentialId);
        if (session.isPresent()) {
            SessionRecord s = session.get();
            if (!s.username().equals(username)) {
                return false;
            }
            return sessionService.revoke(s.sessionId());
        }
        if (tokenService.accessTokenBelongsTo(credentialId, username)) {
            return tokenService.revokeAccessToken(credentialId);
        }
        log.info("credential revoke target not found or not owned user={} id={}", username,
                com.github.h3yow.springauthzgatewayjava.util.Masking.mask(credentialId));
        return false;
    }

    /**
     * 撤销用户名下除指定"当前凭据"之外的全部有效凭据（会话与访问令牌互不影响地各自撤销）。
     * 保留凭据必须属于该用户，否则不保留任何凭据。
     *
     * @return 实际被撤销的凭据数量
     */
    public int revokeOthers(String username, CredentialKind keepKind, String keepCredentialId) {
        if (username == null) {
            return 0;
        }
        String keepSessionId = null;
        String keepAccessJti = null;
        if (keepCredentialId != null) {
            if (keepKind == CredentialKind.SESSION) {
                keepSessionId = sessionService.findByCredentialId(keepCredentialId)
                        .filter(s -> s.username().equals(username))
                        .map(SessionRecord::sessionId)
                        .orElse(null);
            } else if (keepKind == CredentialKind.ACCESS_TOKEN
                    && tokenService.accessTokenBelongsTo(keepCredentialId, username)) {
                keepAccessJti = keepCredentialId;
            }
        }
        int sessions = sessionService.revokeForUserExcept(username, keepSessionId);
        int tokens = tokenService.revokeAllForUserExcept(username, keepAccessJti);
        log.info("revoke-others user={} keepKind={} sessions={} tokens={}",
                username, keepKind, sessions, tokens);
        return sessions + tokens;
    }
}
