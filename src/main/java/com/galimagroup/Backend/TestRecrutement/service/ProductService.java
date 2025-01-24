package com.galimagroup.Backend.TestRecrutement.service;

import com.galimagroup.Backend.TestRecrutement.dto.ProductRequest;
import com.galimagroup.Backend.TestRecrutement.dto.ProductResponse;
import com.galimagroup.Backend.TestRecrutement.entity.Product;
import com.galimagroup.Backend.TestRecrutement.exception.ProductNotFoundException;
import com.galimagroup.Backend.TestRecrutement.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProductService {
    @Autowired
    public ProductRepository productRepository;

    public List<ProductResponse> getProducts() {
        return productRepository.findAll().stream().map(this::mapToProductResponse).toList();
    }

    public ProductResponse getOneProduct(Long id) throws ProductNotFoundException {
        return mapToProductResponse(productRepository.findById(id).orElseThrow( () -> new ProductNotFoundException("No product found with given id !")));
    }

    public ProductResponse createProduct(ProductRequest productRequest){
        Product product = new Product();

        product.setCode(productRequest.getCode());
        product.setName(productRequest.getName());
        product.setDescription(productRequest.getDescription());
        product.setImage(productRequest.getImage());
        product.setCategory(productRequest.getCategory());
        product.setPrice(productRequest.getPrice());
        product.setQuantity(productRequest.getQuantity());
        product.setInternalReference(productRequest.getInternalReference());
        product.setShellId(productRequest.getShellId());
        product.setInventoryStatus(productRequest.getInventoryStatus());
        product.setRating(0);

        try {
            productRepository.save(product);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return mapToProductResponse(product);
    }


    public void deleteProduct(Long id) {

        Product product = productRepository.findById(id).orElseThrow(() -> new ProductNotFoundException("No product found with given id !"));

        productRepository.delete(product);
    }


    public ProductResponse updateProduct(Long id, ProductRequest dto){
        Product product = productRepository.findById(id).orElseThrow(() -> new ProductNotFoundException("No product found with given id !"));

        if (dto.getName() != null) {
            product.setName(dto.getName());
        }
        if (dto.getCode() != null) {
            product.setCode(dto.getCode());
        }
        if (dto.getDescription() != null) {
            product.setDescription(dto.getDescription());
        }
        if (dto.getImage() != null) {
            product.setImage(dto.getImage());
        }
        if (dto.getCategory() != null) {
            product.setCategory(dto.getCategory());
        }
        if (dto.getPrice() != null) {
            product.setPrice(dto.getPrice());
        }
        if (dto.getQuantity() != null) {
            product.setQuantity(dto.getQuantity());
        }
        if (dto.getShellId() != null) {
            product.setShellId(dto.getShellId());
        }
        if (dto.getInventoryStatus() != null) {
            product.setInventoryStatus(dto.getInventoryStatus());
        }
        if (dto.getInternalReference() != null) {
            product.setInternalReference(dto.getInternalReference());
        }

        return mapToProductResponse(productRepository.save(product));
    }

    public ProductResponse mapToProductResponse(Product product) {
        ProductResponse productResponse = new ProductResponse();

        productResponse.setId(product.getId());
        productResponse.setCode(product.getCode());
        productResponse.setCategory(product.getCategory());
        productResponse.setImage(product.getImage());
        productResponse.setDescription(product.getDescription());
        productResponse.setPrice(product.getPrice());
        productResponse.setName(product.getName());
        productResponse.setRating(product.getRating());
        productResponse.setInternalReference(product.getInternalReference());
        productResponse.setShellId(product.getShellId());
        productResponse.setCreatedAt(product.getCreatedAt());
        productResponse.setUpdatedAt(product.getUpdatedAt());

        return productResponse;
    }


}
