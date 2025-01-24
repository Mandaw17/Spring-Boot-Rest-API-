package com.galimagroup.Backend.TestRecrutement.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class CartLine {
    @Id
    @GeneratedValue
    private Long id;
    @ManyToOne
    private Product product;
    private int quantity;
    @ManyToOne
    @JoinColumn(name="cart_id")
    private Cart cart;

    public Long getId() {
        return id;
    }

    public Product getProduct() {
        return product;
    }

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }
}
