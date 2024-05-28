package com.example.multiauthn.adapter.in.web.security;

import static org.springframework.http.HttpHeaders.REFERER;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class MyAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            String referer = request.getHeader(REFERER);
            if (referer != null) {
                log.warn("User: {} attempted to access the protected URL: {} from: {}", auth.getName(),
                        request.getRequestURI(), referer);
            } else {
                log.warn("User: {} attempted to access the protected URL: {}", auth.getName(), request.getRequestURI());
            }
        }

        response.sendRedirect(request.getContextPath() + "/accessDenied");
    }

}
