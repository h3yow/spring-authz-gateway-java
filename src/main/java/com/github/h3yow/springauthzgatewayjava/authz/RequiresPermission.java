package com.github.h3yow.springauthzgatewayjava.authz;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 标注控制器方法所需的资源与动作权限，可选地要求特定角色。
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequiresPermission {
    String resource();

    String action();

    /** 必需角色；空串表示不要求特定角色。 */
    String role() default "";
}
