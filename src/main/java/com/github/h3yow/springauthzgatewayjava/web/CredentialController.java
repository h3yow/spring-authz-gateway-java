package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.auth.CredentialManager;
import com.github.h3yow.springauthzgatewayjava.auth.TokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 活跃凭据自助管理端点（需认证，见 {@code AccessPolicy}）。
 *
 * <p>列举结果只含公开元数据，不含任何凭据本体；撤销立即生效。
 * 撤销单个凭据不影响其他凭据；"撤销其他全部"保留当前请求所用凭据。
 * 对不存在或不属于当前用户的凭据标识一律返回 204，不泄露凭据归属。
 */
@RestController
@RequestMapping("/api/auth/credentials")
public class CredentialController {

    private static final Logger log = LoggerFactory.getLogger(CredentialController.class);

    /** 凭据公开视图：公开标识、种类、客户端、签发/最近使用/失效时间。 */
    public record CredentialResponse(String credentialId, String kind, String client,
                                     Instant issuedAt, Instant lastUsedAt, Instant expiresAt) {}

    private final CredentialManager credentialManager;
    private final TokenService tokenService;

    public CredentialController(CredentialManager credentialManager, TokenService tokenService) {
        this.credentialManager = credentialManager;
        this.tokenService = tokenService;
    }

    @GetMapping
    public List<CredentialResponse> list(HttpServletRequest http) {
        String username = currentUser(http);
        List<CredentialResponse> credentials = credentialManager.list(username).stream()
                .map(v -> new CredentialResponse(v.credentialId(), v.kind(), v.client(),
                        v.issuedAt(), v.lastUsedAt(), v.expiresAt()))
                .toList();
        log.info("credentials listed user={} count={} correlation={}",
                username, credentials.size(), correlationId(http));
        return credentials;
    }

    /** 撤销单个凭据：立即生效、幂等，不泄露凭据是否存在或归属。 */
    @DeleteMapping("/{credentialId}")
    public ResponseEntity<Void> revokeOne(@PathVariable String credentialId, HttpServletRequest http) {
        credentialManager.revokeOne(currentUser(http), credentialId);
        return ResponseEntity.noContent().build();
    }

    /** 撤销除当前凭据外的全部凭据：立即生效，当前客户端不受影响。 */
    @PostMapping("/revoke-others")
    public ResponseEntity<Void> revokeOthers(HttpServletRequest http) {
        String username = currentUser(http);
        credentialManager.revokeAllExcept(username, currentCredential(http));
        return ResponseEntity.noContent().build();
    }

    private static String currentUser(HttpServletRequest http) {
        AuthContext context = (AuthContext) http.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        if (context == null) {
            throw new IllegalStateException("credentials endpoint requires authentication");
        }
        return context.username();
    }

    /** 识别当前请求所用凭据：会话 Cookie 或 Bearer 访问令牌所属凭据。 */
    private CredentialManager.CurrentCredential currentCredential(HttpServletRequest http) {
        AuthContext context = (AuthContext) http.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        if (context != null && "session".equals(context.credentialKind())) {
            String sessionId = readSessionCookie(http);
            if (sessionId != null) {
                return CredentialManager.CurrentCredential.session(sessionId);
            }
        }
        String header = http.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return tokenService.credentialIdOf(header.substring(7).trim())
                    .map(CredentialManager.CurrentCredential::token)
                    .orElse(null);
        }
        return null;
    }

    private static String readSessionCookie(HttpServletRequest http) {
        if (http.getCookies() == null) {
            return null;
        }
        for (Cookie c : http.getCookies()) {
            if (AuthFilter.SESSION_COOKIE.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    private static String correlationId(HttpServletRequest http) {
        Object id = http.getAttribute(AuthFilter.CORRELATION_ATTRIBUTE);
        return id != null ? id.toString() : "unknown";
    }
}
