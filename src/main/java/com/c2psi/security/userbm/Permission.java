package com.c2psi.security.userbm;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Permission {
    ADMIN_READ("admin:Read"),
    ADMIN_POST("admin:Create"),
    ADMIN_PUT("admin:Update"),
    ADMIN_DELETE("admin:Delete"),
    MANAGER_READ("management:Read"),
    MANAGER_POST("management:Create"),
    MANAGER_PUT("management:Update"),
    MANAGER_DELETE("management:Delete")

    ;

    @Getter
    private final String permission;
}
