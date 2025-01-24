package com.galimagroup.Backend.TestRecrutement.service;

import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

@SpringBootTest
//@ExtendWith(MockitoExtension.class)
class ProductServiceTestae {

//    @Mock
//    private ProductRepository productRepository;
//    @InjectMocks
//    @Mock
//    private ProductService productService;
//
//    private Product product1;
//    private Product product2;
//
//    @BeforeTestClass
//    public void setUp() {
//
//        Product product1 = new Product();
//        product1.setId(1L);
//        product1.setCode("p1_2k25");
//        product1.setName("Product1");
//        product1.setDescription("Description1");
//        product1.setImage("some_url");
//        product1.setCategory("category1");
//        product1.setPrice(100L);
//        product1.setQuantity(10);
//        product1.setInternalReference("someref1");
//        product1.setShellId(12212L);
//        product1.setInventoryStatus(InventoryStatus.INSTOCK);
//        product1.setRating(0);
//
//        Product product2 = new Product();
//        product2.setId(2L);
//        product2.setCode("p2_2k25");
//        product2.setName("Product2");
//        product2.setDescription("Description2");
//        product2.setImage("some_url");
//        product2.setCategory("category1");
//        product2.setPrice(1000L);
//        product2.setQuantity(10);
//        product2.setInternalReference("someref2");
//        product2.setShellId(12213L);
//        product2.setInventoryStatus(InventoryStatus.INSTOCK);
//        product2.setRating(0);
//    }
//
//    @Test
//    void getProducts() {
//        // Given
//
//        when(productRepository.findAll().stream()).thenReturn((Stream<Product>) Arrays.asList(product1, product2));
//        // When
//        List<ProductResponse> products = productService.getProducts();
//        // Then
//        assertThat(products).hasSize(2);
//        assertThat(products.get(0).getName()).isEqualTo("Product1");
//        assertThat(products.get(1).getName()).isEqualTo("Product2");
//    }
//
//    @Test
//    void getOneProduct() {
//        // Given
//        when(productRepository.findById(1L).orElseThrow()).thenReturn(product1);
//        // When
//        ProductResponse productResponse = this.productService.getOneProduct(1L);
//        // Then
//        assertThat(productResponse.getName()).isEqualTo("Product1");
//    }
//
//    @Test
//    void createProduct() {
//        // Given
//
//        // When
//
//        // Then
//    }
//
//
//    @Test
//    void deleteProduct() {
//        // Given
//
//        // When
//
//        // Then
//    }
//
//    @Test
//    void updateProduct() {
//        // Given
//
//        // When
//
//        // Then
//    }
}