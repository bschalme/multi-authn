package com.example.multiauthn.adapter.in.web.security;

import java.io.IOException;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private Set<String> userRoles = Set.of("ROLE_USER", "OAUTH2_USER", "ROLE_user");

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            redirectStrategy.sendRedirect(request, response, "/admin");
            return;
        }
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> userRoles.contains(a.getAuthority()))) {
            redirectStrategy.sendRedirect(request, response, "/user");
        }
    }

}
