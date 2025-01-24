package com.galimagroup.Backend.TestRecrutement.service;

import com.galimagroup.Backend.TestRecrutement.entity.Product;
import com.galimagroup.Backend.TestRecrutement.entity.Wishlist;
import com.galimagroup.Backend.TestRecrutement.repository.WishlistRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class WishlistService {
    @Autowired
    public WishlistRepository wishlistRepository;

    public List<Wishlist> getWishlists() {
        return wishlistRepository.findAll();
    }

    public List<Wishlist> getWishedProducts(String userId) {
        return wishlistRepository.findByUserId(userId);
    }

    public Wishlist createWishlist(Wishlist wishlist) {
        return wishlistRepository.save(wishlist);
    }
}
