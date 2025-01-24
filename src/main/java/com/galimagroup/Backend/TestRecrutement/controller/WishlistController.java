package com.galimagroup.Backend.TestRecrutement.controller;


import com.galimagroup.Backend.TestRecrutement.entity.Wishlist;
import com.galimagroup.Backend.TestRecrutement.service.WishlistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;


@RestController
public class WishlistController {

    @Autowired
    public WishlistService wishlistService;

    @RequestMapping(value = "wishlist", method = RequestMethod.POST)
    public ResponseEntity<Wishlist> createWishlist (@RequestBody Wishlist wishlist, @AuthenticationPrincipal Jwt jwt) {
        String userId = jwt.getSubject();
        wishlist.setUserId(userId);
        return ResponseEntity.status(HttpStatus.CREATED).body(wishlistService.createWishlist(wishlist)) ;
    }

    @GetMapping(value = "wishlist")
    public ResponseEntity<List<Wishlist>> getUserWishlists(@AuthenticationPrincipal Jwt jwt) {
        String userId = jwt.getSubject(); // Extract user ID from the token
        return ResponseEntity.ok(wishlistService.getWishedProducts(userId));
    }
}
