package com.galimagroup.Backend.TestRecrutement.controller;


import com.galimagroup.Backend.TestRecrutement.dto.ProductRequest;
import com.galimagroup.Backend.TestRecrutement.dto.ProductResponse;
import com.galimagroup.Backend.TestRecrutement.entity.Product;
import com.galimagroup.Backend.TestRecrutement.exception.ErrorResponse;
import com.galimagroup.Backend.TestRecrutement.service.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class ProductController {
    @Autowired
    public ProductService productService;

    @RequestMapping(value = "products", method = RequestMethod.GET)
    public List<ProductResponse> getAllProducts() {
        return productService.getProducts();
    }

    @RequestMapping(value = "products", method = RequestMethod.POST)
    public ProductResponse addProduct(@RequestBody ProductRequest productRequest) {
        return productService.createProduct(productRequest);
    }

    @RequestMapping(value = "products/{id}")
    public ProductResponse getOneProduct(@PathVariable Long id){
        return productService.getOneProduct(id);
    }

    @DeleteMapping(value = "products/{id}")
    public ErrorResponse deleteProduct(@PathVariable  Long id) {
        productService.deleteProduct(id);
        return new ErrorResponse("Product successfully deleted !", HttpStatus.OK.value(), System.currentTimeMillis());
    }

    @PatchMapping(value = "products/{id}")
    public ProductResponse updateEntity(@PathVariable Long id, @RequestBody ProductRequest dto) {
        return productService.updateProduct(id, dto);
    }

}

