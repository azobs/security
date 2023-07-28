package com.c2psi.security.userbm;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserbmRepository extends JpaRepository<Userbm, Long> {
    Optional<Userbm> findByEmail(String email);
}
