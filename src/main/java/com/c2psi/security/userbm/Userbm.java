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
@Table(name = "userbm",
        uniqueConstraints = {@UniqueConstraint(
                columnNames = {"email"})})
public class Userbm implements UserDetails {
    @Id
    @GeneratedValue
    Long id;
    @Column(nullable = false)
    String firstName;
    String lastName;
    @Column(nullable = false)
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
        //Ce return qui etait la avant les modif du 29-07-2023 concernant les permissions
        //return List.of(new SimpleGrantedAuthority(role.name()));
        //Ajout du 29-07-2023
        return role.getAuthorities();
        //Fin des ajouts
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
