package com.galimagroup.Backend.TestRecrutement.repository;

import com.galimagroup.Backend.TestRecrutement.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthRepository extends JpaRepository<User, Long> {
    User findByEmail(String email);
    User existsByEmail(String email);
    User existsByUsername(String usermame);
}
