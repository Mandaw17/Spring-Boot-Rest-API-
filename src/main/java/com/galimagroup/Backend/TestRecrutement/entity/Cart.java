package com.galimagroup.Backend.TestRecrutement.entity;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;

@Entity
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Cart {
    @Id
    @GeneratedValue
    private Long id;
    private String userId;
    @OneToMany(mappedBy = "cart")
    private ArrayList<CartLine> lines;
    private Long total = 0L;

    public Long getId() {
        return id;
    }

    public ArrayList<CartLine> getLines() {
        return lines;
    }

    public Long getTotal() {
        return total;
    }

    public Long calculateTotal() {
        for (CartLine cartLine: lines) {
            total += cartLine.getProduct().getPrice();
        }

        return total;
    }
}
