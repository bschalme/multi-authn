package com.example.multiauthn.adapter.in.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Controller
public class UserController {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user")
    public String userHome(Authentication authn) {
        OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient("keycloak",
                authn.getName());

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
        OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
        log.debug("Access token = {}", accessToken.getTokenValue());
        log.debug("Refresh token = {}", refreshToken != null ? refreshToken.getTokenValue() : "(null)");
        return "user";
    }
}
