package com.galimagroup.Backend.TestRecrutement.service;


import com.galimagroup.Backend.TestRecrutement.dto.UserRegistrationRequest;
import com.galimagroup.Backend.TestRecrutement.entity.User;
import com.galimagroup.Backend.TestRecrutement.exception.ErrorResponse;
import com.galimagroup.Backend.TestRecrutement.exception.GlobalBadRequestException;
import com.galimagroup.Backend.TestRecrutement.repository.AuthRepository;
import com.galimagroup.Backend.TestRecrutement.util.PasswordValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuthService {
    @Autowired
    private AuthRepository authRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${keycloak.auth-server-url}")
    private String keycloakBaseUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.admin-client-id}")
    private String clientId;
    @Value("${keycloak.admin-client-secret}")
    private String clientSecret;
    @Value("${keycloak.admin-username}")
    private String adminUsername;
    @Value("${keycloak.admin-password}")
    private String adminPassword;
    @Value("${keycloak.login-url}")
    private String loginUrl;

    public String getAdminToken() {
        String tokenUrl = keycloakBaseUrl + "/realms/"+realm+"/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                tokenUrl, HttpMethod.POST, request, Map.class
        );

        if (response.getStatusCode() == HttpStatus.OK) {
            return response.getBody().get("access_token").toString();
        }

        throw new RuntimeException("Failed to retrieve admin token");
    }


    public String getUserId(String username) {
        String token = getAdminToken(); // Admin token for authentication
        String usersUrl = keycloakBaseUrl + "/admin/realms/" + realm + "/users?username=" + username;

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        ResponseEntity<List> response = restTemplate.exchange(
                usersUrl, HttpMethod.GET, request, List.class
        );

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null && !response.getBody().isEmpty()) {
            Map user = (Map) response.getBody().get(0); // Keycloak returns a list, we take the first entry
            return user.get("id").toString();
        }

        throw new RuntimeException("User not found with username: " + username);
    }



    public ResponseEntity<String> registerUser(UserRegistrationRequest userRegistrationRequest) {
        String token = getAdminToken();
        String createUserUrl = keycloakBaseUrl + "/admin/realms/" + realm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        Map<String, Object> user = new HashMap<>();
        user.put("username", userRegistrationRequest.getUsername());
        user.put("email", userRegistrationRequest.getEmail());
        user.put("firstName", userRegistrationRequest.getFirstName());
        user.put("lastName", userRegistrationRequest.getLastName());
        user.put("enabled", true);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);

        ResponseEntity<String> response = restTemplate.exchange(
                createUserUrl, HttpMethod.POST, request, String.class
        );

        if (response.getStatusCode() != HttpStatus.CREATED) {
            throw new RuntimeException("Failed to register user");
        }
        return response;
    }


    public void setPassword(String userId, String password) {

        String token = getAdminToken();
        String passwordUrl = keycloakBaseUrl + "/admin/realms/" + realm + "/users/" + userId + "/reset-password";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(token);

        Map<String, Object> passwordData = new HashMap<>();
        passwordData.put("type", "password");
        passwordData.put("value", password);
        passwordData.put("temporary", false);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(passwordData, headers);

        ResponseEntity<Void> response = restTemplate.exchange(
                passwordUrl, HttpMethod.PUT, request, Void.class
        );

        if (response.getStatusCode() != HttpStatus.NO_CONTENT) {
            throw new RuntimeException("Failed to set user password");
        }
    }


    public void registerUserWithPassword(UserRegistrationRequest userRegistrationRequest) {
        String validationMessage = PasswordValidator.getValidationMessage(userRegistrationRequest.getPassword(), userRegistrationRequest.getPasswordConfirmation());
        if (validationMessage != null) {
            System.out.println("IS  IT HERE ?");
            throw new IllegalArgumentException(validationMessage); // Reject invalid passwords
        }

        // Step 1: Register the user

        ResponseEntity<String> registerResponse = registerUser(userRegistrationRequest);

        // Step 2: Fetch the userId
        if (registerResponse.getStatusCode() == HttpStatus.CREATED) {
            String userId = getUserId(userRegistrationRequest.getUsername());
            // Step 3: Set the password
            setPassword(userId, userRegistrationRequest.getPassword());
        }

    }

    public ResponseEntity<Map> loginUser(String email, String password) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String token = getAdminToken();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "password");
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("email", email);
        form.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                loginUrl, HttpMethod.POST, request, Map.class
        );

        if (response.getStatusCode() == HttpStatus.OK) {
            return ResponseEntity.ok().body(response.getBody());
        }

        throw new GlobalBadRequestException("Cannot login with given credentials");
    }


}
