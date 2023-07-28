package com.c2psi.security.userbm;

import com.c2psi.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "userbm")
public class Userbm implements UserDetails {
    @Id
    @GeneratedValue
    Long id;
    @Column(nullable = false)
    String firstName;
    String lastName;
    @Column(nullable = false, unique = true)
    String email;
    @Column(nullable = false)
    String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    /**************************
     * Relation to other entity
     */
    @OneToMany(mappedBy = "userbm")
    private List<Token> tokenList;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    } //Not false to avoid org.springframework.security.authentication.DisableException'
}
