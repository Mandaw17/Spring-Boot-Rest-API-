package com.galimagroup.Backend.TestRecrutement.repository;

import com.galimagroup.Backend.TestRecrutement.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ProductRepository extends JpaRepository<Product, Long> {
    public Optional<Product> findById(Long id);
    public void deleteById(Long id);
}
