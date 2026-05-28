package com.example.edustream_lib_security.exception;

import com.example.edustream_lib_common.responseDTO.ErrorResponseDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        response.setStatus(403);
        response.setContentType("application/json");
        response.getOutputStream().println(
                "{\"status\": 403, \"message\": \"Access denied. You do not have permission to access this resource.\"}"
        );
    }
}