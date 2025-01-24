package com.galimagroup.Backend.TestRecrutement.util;

import jakarta.ws.rs.core.Response;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
//import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class KeycloakService {

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin-client-id}")
    private String clientId;

    @Value("${keycloak.admin-client-secret}")
    private String clientSecret;

    @Value("${keycloak.admin-username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin-password:admin}")
    private String adminPassword;

//    public void registerUser(String username, String email, String password, String firstName) {
//        Keycloak keycloak = KeycloakBuilder.builder()
//                .serverUrl(serverUrl)
//                .realm("master")  // Use "master" for admin operations
//                .clientId(clientId)
//                .clientSecret(clientSecret)
//                .username(adminUsername)
//                .password(adminPassword)
//                .build();
//
//        UserRepresentation user = new UserRepresentation();
//        user.setUsername(username);
//        user.setEmail(email);
//        user.setFirstName(firstName);
//        user.setEnabled(true);
//
//        CredentialRepresentation credentials = new CredentialRepresentation();
//        credentials.setType(CredentialRepresentation.PASSWORD);
//        credentials.setValue(password);
//        credentials.setTemporary(false);
//
//        user.setCredentials(Collections.singletonList(credentials));
//
//        Response response = keycloak.realm(realm).users().create(user);
//
//        if (response.getStatus() != 201) {
//            throw new RuntimeException("Failed to create user: " + response.getStatusInfo());
//        }
//    }
}
