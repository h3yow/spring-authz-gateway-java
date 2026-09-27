package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.CredentialInfo;
import com.github.h3yow.springauthzgatewayjava.auth.CredentialService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 活跃凭据自助管理端点（位于 {@code /api/user/**}，需 USER 或 ADMIN）。
 *
 * <p>列表仅返回元数据（对外管理句柄、来源、签发/最近使用/失效时间），
 * 不返回会话标识或令牌原文。撤销操作只能作用于当前用户名下的凭据。
 */
@RestController
@RequestMapping("/api/user/credentials")
public class CredentialController {

    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    private final CredentialService credentialService;

    public CredentialController(CredentialService credentialService) {
        this.credentialService = credentialService;
    }

    public record RevokeRequest(String id) {}
    public record CredentialView(String id, String kind, String clientKey,
                                 String issuedAt, String lastUsedAt, String expiresAt) {
        static CredentialView from(CredentialInfo info) {
            return new CredentialView(info.id(), info.kind().name(), info.clientKey(),
                    info.issuedAt().toString(), info.lastUsedAt().toString(), info.expiresAt().toString());
        }
    }

    /** 查看自己名下当前仍然有效的全部凭据（会话与访问令牌）。 */
    @GetMapping
    public List<CredentialView> list(HttpServletRequest http) {
        AuthContext context = currentUser(http);
        List<CredentialView> views = credentialService.listActive(context.username())
                .stream().map(CredentialView::from).toList();
        log.info("list active credentials user={} count={}", context.username(), views.size());
        return views;
    }

    /** 撤销自己名下的单个凭据，不影响其他客户端；重复撤销幂等。 */
    @PostMapping("/revoke")
    public Map<String, Object> revoke(@RequestBody RevokeRequest request, HttpServletRequest http) {
        AuthContext context = currentUser(http);
        boolean revoked = credentialService.revokeCredential(context.username(), request.id());
        log.info("credential revoke requested user={} revoked={}", context.username(), revoked);
        return Map.of("revoked", revoked);
    }

    /** 一键撤销除"当前请求所用凭据"之外的全部凭据；当前客户端保持可用。 */
    @PostMapping("/revoke-others")
    public Map<String, Object> revokeOthers(HttpServletRequest http) {
        AuthContext context = currentUser(http);
        int count = credentialService.revokeOthers(
                context.username(), context.kind(), context.credentialRef());
        log.info("revoke-others user={} keepKind={} revokedCount={}",
                context.username(), context.kind(), count);
        return Map.of("revokedCount", count);
    }

    private static AuthContext currentUser(HttpServletRequest http) {
        return (AuthContext) http.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
    }
}
