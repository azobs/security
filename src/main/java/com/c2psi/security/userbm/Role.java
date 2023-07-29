package com.c2psi.security.userbm;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.c2psi.security.userbm.Permission.*;

@RequiredArgsConstructor
public enum Role {
    Admin(
            Set.of(
                    ADMIN_READ,
                    ADMIN_POST,
                    ADMIN_PUT,
                    ADMIN_DELETE,
                    MANAGER_READ,
                    MANAGER_POST,
                    MANAGER_PUT,
                    MANAGER_DELETE
            )
    ),

    Manager(
            Set.of(
                    MANAGER_READ,
                    MANAGER_POST,
                    MANAGER_PUT,
                    MANAGER_DELETE
            )
    ),

    User(Collections.emptySet())
    ;
    @Getter
    private final Set<Permission> permissionSet;

    public List<SimpleGrantedAuthority> getAuthorities(){
        var authorities = getPermissionSet()
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return authorities;
    }
}
