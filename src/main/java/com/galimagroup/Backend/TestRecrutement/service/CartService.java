package com.galimagroup.Backend.TestRecrutement.service;

import com.galimagroup.Backend.TestRecrutement.entity.Cart;
import com.galimagroup.Backend.TestRecrutement.entity.Product;
import com.galimagroup.Backend.TestRecrutement.repository.CartRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CartService {

    @Autowired
    public CartRepository cartRepository;

    public Cart addProductToCart(Product product, int quantity) {
        return null;
    }

    public Cart emptyCart() {
        return null;
    }

    public Cart getCart(String user_id) {
        return cartRepository.findByUserId(user_id);
    }
}
