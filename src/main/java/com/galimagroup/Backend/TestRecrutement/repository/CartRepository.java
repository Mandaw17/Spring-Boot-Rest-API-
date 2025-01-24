package com.galimagroup.Backend.TestRecrutement.repository;

import com.galimagroup.Backend.TestRecrutement.entity.Cart;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CartRepository extends JpaRepository<Cart, Long> {
    Cart findByUserId(String userId);
}
