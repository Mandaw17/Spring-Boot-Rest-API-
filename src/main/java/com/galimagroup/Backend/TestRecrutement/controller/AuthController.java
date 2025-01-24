package com.galimagroup.Backend.TestRecrutement.controller;

import com.galimagroup.Backend.TestRecrutement.dto.UserLoginRequest;
import com.galimagroup.Backend.TestRecrutement.dto.UserRegistrationRequest;
import com.galimagroup.Backend.TestRecrutement.entity.User;
import com.galimagroup.Backend.TestRecrutement.service.AuthService;
import com.galimagroup.Backend.TestRecrutement.util.JwtUtil;
import com.galimagroup.Backend.TestRecrutement.util.KeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthController {

    @Autowired
    private AuthService authService;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/account")
    public ResponseEntity<String> register(@RequestBody UserRegistrationRequest user) {
        authService.registerUserWithPassword(user);
        return ResponseEntity.status(201).body("User registered successfully");
    }

    @PostMapping("/token")
    public ResponseEntity<Map> login(@RequestBody UserLoginRequest user) {


        ResponseEntity<Map> authenticatedUser = authService.loginUser(user.getEmail(), user.getPassword());

        return authenticatedUser;
    }



}
