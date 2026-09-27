package com.github.h3yow.springauthzgatewayjava.auth;

/**
 * 凭据生命周期状态判定，稳定且可区分：
 * <ul>
 *   <li>{@link #VALID} 有效；</li>
 *   <li>{@link #REVOKED} 曾存在但已被撤销（墓碑可判定）；</li>
 *   <li>{@link #EXPIRED} 已超过失效时间；</li>
 *   <li>{@link #UNKNOWN} 注册表无此凭据或签名/格式不被认可（可能是服务端早已不认可的旧凭据）。</li>
 * </ul>
 */
public enum CredentialState {
    VALID,
    REVOKED,
    EXPIRED,
    UNKNOWN
}
