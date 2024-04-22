package com.example.multiauthn;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationSuccessHandler myAuthenticationSuccessHandler;

    private final LogoutSuccessHandler myLogoutSuccessHandler;

    private final AuthenticationFailureHandler authenticationFailureHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .headers(h -> {
                    h.frameOptions(FrameOptionsConfig::sameOrigin);
                })
                .authorizeHttpRequests(authz -> {
                    authz.requestMatchers("/", "/favicon.ico", "/h2-console/**", "/login*", "/logout*", "/loggedout*",
                            "/user/registration*")
                            .permitAll()
                            .requestMatchers("/home")
                            .authenticated()
                            .requestMatchers("/admin")
                            .hasAnyAuthority("ROLE_ADMIN")
                            .requestMatchers("/user")
                            .hasAnyAuthority("ROLE_ADMIN", "ROLE_USER");
                })
                .formLogin(formLogin -> formLogin.loginPage("/login")
                        .successHandler(myAuthenticationSuccessHandler)
                        // .defaultSuccessUrl("/home", true)
                        .failureUrl("/login?error=true")
                        .failureHandler(authenticationFailureHandler)
                        .permitAll())
                .logout(logout -> logout.logoutSuccessHandler(myLogoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .logoutSuccessUrl("/logout.html?logSucc=true")
                        .deleteCookies("JSESSIONID")
                        .permitAll());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(11);
    }

}
