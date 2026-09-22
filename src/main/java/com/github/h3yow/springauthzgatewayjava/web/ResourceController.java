package com.github.h3yow.springauthzgatewayjava.web;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 示例资源，用于验证基于角色与资源的授权：
 * <ul>
 *   <li>{@code /api/public/**} 公开；</li>
 *   <li>{@code /api/user/**} 需 USER 或 ADMIN；</li>
 *   <li>{@code /api/admin/**} 需 ADMIN；</li>
 *   <li>其余路径缺省拒绝。</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public/info")
    public Map<String, Object> publicInfo() {
        return Map.of("scope", "public", "message", "no authentication required");
    }

    @GetMapping("/user/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        AuthContext context = (AuthContext) request.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        return Map.of("username", context.username(), "roles", context.roles(),
                "credentialKind", context.credentialKind());
    }

    /** 改变状态请求：用于验证 CSRF 防护。 */
    @PostMapping("/user/profile")
    public Map<String, Object> updateProfile(HttpServletRequest request) {
        AuthContext context = (AuthContext) request.getAttribute(AuthContext.REQUEST_ATTRIBUTE);
        return Map.of("updated", true, "username", context.username());
    }

    @GetMapping("/admin/stats")
    public Map<String, Object> adminStats() {
        return Map.of("scope", "admin", "activeUsers", 3);
    }
}
