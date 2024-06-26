package com.example.multiauthn.adapter.in.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Controller
public class UserController {

    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/user")
    public ModelAndView userHome(Authentication authn) {
        OAuth2AuthorizedClient authorizedClient = this.authorizedClientService.loadAuthorizedClient("keycloak",
                authn.getName());

        if (authorizedClient != null) {
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            log.debug("Access token = {}", accessToken.getTokenValue());
            log.debug("Refresh token = {}", refreshToken != null ? refreshToken.getTokenValue() : "(null)");
        } else {
            log.warn("No authorized client found for user {}", authn.getName());
        }
        ModelMap modelMap = new ModelMap("user", authn.getPrincipal());
        return new ModelAndView("user", modelMap);
    }
}
