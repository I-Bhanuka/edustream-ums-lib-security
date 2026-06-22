package com.example.edustream_lib_security.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Utility class to extract user information from Spring Security context
 */
@Component
@Slf4j
public class SecurityContextUtil {

    /**
     * Get the current authenticated user ID as String
     */
    public Optional<String> getCurrentUserIdAsString() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info(SecurityContextHolder.getContext().getAuthentication().toString());
        if (authentication != null && authentication.isAuthenticated()
                && !"anonymousUser".equals(authentication.getPrincipal())) {
            log.info("Current user: {}", authentication.getPrincipal());
            return Optional.of(authentication.getName());
        }

        log.info("No authenticated user found in security context");
        return Optional.empty();
    }

    /**
     * Get the current authenticated user ID as UUID
     * Returns empty Optional if user is not authenticated or if the ID is not a valid UUID
     */
    public Optional<String> getCurrentUserId() {
        return getCurrentUserIdAsString();
    }

    /**
     * Get the current user's roles
     */
    public List<String> getCurrentUserRoles() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        }
        return List.of();
    }

    /**
     * Check if current user has a specific role
     */
    public boolean hasRole(String role) {
        return getCurrentUserRoles().contains(role);
    }

    /**
     * Check if current user has any of the specified roles
     */
    public boolean hasAnyRole(String... roles) {
        List<String> userRoles = getCurrentUserRoles();
        for (String role : roles) {
            if (userRoles.contains(role)) {
                return true;
            }
        }
        return false;
    }
}

