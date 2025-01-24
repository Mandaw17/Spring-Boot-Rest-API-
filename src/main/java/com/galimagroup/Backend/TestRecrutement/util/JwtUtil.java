package com.galimagroup.Backend.TestRecrutement.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.security.Key;
import io.jsonwebtoken.security.Keys;



@Component
public class JwtUtil {
    private static final SecretKey SECRET_KEY = io.jsonwebtoken.security.Keys.secretKeyFor(SignatureAlgorithm.HS256);
    private static final long EXPIRATION_TIME = 3600000; // 1 hour


    public static String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600 * 1000)) // 1 hour expiration
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY.getEncoded())
                .compact();
    }


    public static boolean isTokenValid(String token, String mail) {

        try {
            Key key = Keys.hmacShaKeyFor(SECRET_KEY.getEncoded());
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key) // Use the builder API
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Extract claims
            String email = claims.getSubject();
            System.out.println(email);
            Date expiration = claims.getExpiration();

            // Check if the token has expired
            if (expiration.before(new Date())) {
                System.out.println("Token expired");
                return false;
            }

            // Check if the user's role matches the required role
            return mail.equals(email);

        } catch (Exception e) {
            System.out.println("Error validating token: " + e.getMessage());
            return false;
        }
    }



    public String extractEmail(String token) {
        Key key = Keys.hmacShaKeyFor(SECRET_KEY.getEncoded());
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key) // Use the builder API
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }
}
