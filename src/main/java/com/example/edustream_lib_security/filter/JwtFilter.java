package com.example.edustream_lib_security.filter;

import com.example.edustream_lib_security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 *
 * This class is to implement the Jwt filer into the security filter chain.
 * It will use the JwtUtil to validate the token and extract the username from the token.
 * And if the authentication is successful, it will set the authentication in the security context for the current request.
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    // OncePerRequestFilter means it will intervene per every request

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        log.info("======> JWT Filter executing for request: {} {}", request.getMethod(), request.getRequestURI());

        // 1. Look for the Authorization header
        String authHeader = request.getHeader("Authorization");

        // 2. No token? Skip this filter entirely — pass request forward
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Authorization header not present");
            log.info("Skipping JWT filter for this request");
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Strip "Bearer " prefix to get the raw token
        String token = authHeader.substring(7);

        // 4. Validate the token
        String username = null;
        if (jwtUtil.validateToken(token)) {
            // 5. Extract the username baked into the token
            username = jwtUtil.extractUsername(token);
            log.info("Token valid for user: {}", username);

            // 6. Create an Authentication object with the username and empty authorities
            // UsernamePasswordAuthenticationToken with null passed as for password means an authenticated user in the application
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            username,
                            null, // No password needed here because we have already validated the token
                            Collections.emptyList());

            // 7. Set the authentication in the SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("Authentication set in security context for user: {}", username);
        } else {
            log.warn("Invalid token for user: {}", username);
        }

        // 7. Pass the request to the next filter in the chain
        log.info("Passing request to next filter in chain");
        filterChain.doFilter(request, response);
    }
}

