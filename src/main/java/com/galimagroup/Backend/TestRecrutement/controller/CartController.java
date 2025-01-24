package com.galimagroup.Backend.TestRecrutement.controller;

import com.galimagroup.Backend.TestRecrutement.entity.Cart;
import com.galimagroup.Backend.TestRecrutement.service.CartService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CartController {
    @Autowired
    public CartService cartService;

    public ResponseEntity<Cart> getCart(@AuthenticationPrincipal Jwt jwt) {
        String userId = jwt.getSubject(); // Extract user ID from the token
        return ResponseEntity.ok(cartService.getCart(userId));
    }
}
