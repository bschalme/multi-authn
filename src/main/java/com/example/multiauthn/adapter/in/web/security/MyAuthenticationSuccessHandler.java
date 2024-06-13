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
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private Set<String> userRoles = Set.of("ROLE_USER", "OAUTH2_USER", "ROLE_user");
    private Set<String> adminRoles = Set.of("ROLE_ADMIN", "ROLE_admin");

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> adminRoles.contains(a.getAuthority()))) {
            redirectStrategy.sendRedirect(request, response, "/admin");
            return;
        }
        if (authentication.getAuthorities().stream()
                .anyMatch(a -> userRoles.contains(a.getAuthority()))) {
            redirectStrategy.sendRedirect(request, response, "/user");
            return;
        }
        log.warn("User: {} has no roles assigned", authentication.getName());
        redirectStrategy.sendRedirect(request, response, "/noRolesAssigned");
    }

}
