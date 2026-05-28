package com.example.edustream_lib_security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

/**
 *
 * This is just a utility file which helps to,
 * 1. Generate the JWT token
 * 2. Extract the username from the token
 * 3. Validate the token and check if the token is expired or not.
 */

@Component
public class JwtUtil {

    // Signature of token is generated using this secret key.
    private static final String SECRET =
            "your-very-secret-key-that-is-long-enough-for-hs256";

    // Token validity: 24 hours
    private static final long EXPIRATION_MS = 86400000;

    // Generate the signing key from the secret
    private SecretKey getSigningKey() {
        // HMAC - Hash-based Message Authentication Code
        return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    // Method to generate a JWT token for a given user
    public String generateToken(String username, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(username)                  // Subject claim is the username
                .claim("role", role)             // Add our custom claim for user role
                .issuedAt(Date.from(now))           // iat claim
                .expiration(Date.from(now.plusMillis(EXPIRATION_MS))) // exp claim (now + 24hrs)
                .signWith(getSigningKey())
                .compact();                         // signs everything above with HMAC-SHA256
    }

    // Validate the token
    public boolean validateToken(String token) {
        try {
            extractClaims(token); // If this doesn't throw an exception, the token is valid
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("Token expired");
        } catch (UnsupportedJwtException e) {
            System.out.println("Token unsupported");
        } catch (MalformedJwtException e) {
            System.out.println("Token malformed");
        } catch (SignatureException e) {
            System.out.println("Signature invalid");
        } catch (IllegalArgumentException e) {
            System.out.println("Token empty or null");
        }

        return false;
    }

    // Extract the username (subject) from the token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // Extract the user role from the token
    public String extractUserRole(String token) {
        return extractClaims(token).get("role", String.class);
    }

    // A Private method to extract claims from the token
    private Claims extractClaims(String token) {
        return Jwts.parser()                // Start the parser
                .verifyWith(getSigningKey())// Tells which secret key to use for verifying the signature
                .build()                    // Build the parser
                .parseSignedClaims(token)   // Decode + verify the token
                .getPayload();              // Extract the claims (payload)
    }

}
