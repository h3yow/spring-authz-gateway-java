package com.github.h3yow.springauthzgatewayjava.web;

import com.github.h3yow.springauthzgatewayjava.authz.RequiresPermission;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 受保护资源端点：用于验证认证、角色与资源权限判定。
 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    @GetMapping("/me")
    @RequiresPermission(resource = "profile", action = "read")
    public Map<String, Object> me(HttpServletRequest request) {
        AuthContext ctx = AuthContext.from(request);
        return Map.of(
                "username", ctx.user().username(),
                "roles", ctx.user().roles(),
                "credentialKind", ctx.credentialKind());
    }

    @GetMapping("/documents/{id}")
    @RequiresPermission(resource = "documents", action = "read")
    public Map<String, Object> document(@PathVariable String id) {
        return Map.of("id", id, "content", "document-" + id);
    }

    @PostMapping("/documents")
    @RequiresPermission(resource = "documents", action = "write")
    public Map<String, Object> createDocument() {
        return Map.of("status", "created");
    }

    @GetMapping("/admin/stats")
    @RequiresPermission(resource = "admin", action = "read", role = "ADMIN")
    public Map<String, Object> adminStats() {
        return Map.of("users", 4, "note", "admin only");
    }
}
