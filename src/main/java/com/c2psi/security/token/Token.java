package com.c2psi.security.token;

import com.c2psi.security.userbm.Userbm;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "token")
public class Token {
    @Id
    @GeneratedValue
    private Long id;
    @Column(nullable = false, unique = true)
    private String token;
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;
    private boolean expired;
    private boolean revoked;

    /**************************
     * Relation to other entity
     */
    @ManyToOne
    @JoinColumn(name = "userbmId")
    private Userbm userbm;
}
