package com.c2psi.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    @Query("""
SELECT t FROM Token t WHERE t.userbm.id = :userbmId AND (t.expired = false OR t.revoked = false)
""")
    List<Token> findAllValidTokenListByUser(Long userbmId);

    Optional<Token> findByToken(String token);
}
