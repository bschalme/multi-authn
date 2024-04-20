package com.example.multiauthn.adapter.in.web.controller;

import java.util.Locale;
import java.util.Optional;

import org.springframework.context.MessageSource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.ModelAndView;

import com.example.multiauthn.application.port.in.RegistrationUseCase;
import com.example.multiauthn.domain.UserDto;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class RegistrationController {

    private final MessageSource messages;

    private final RegistrationUseCase registrationUseCase;

    @GetMapping("/user/registration")
    public String showRegistrationForm(WebRequest request, Model model) {
        UserDto userDto = UserDto.builder()
                .build();
        model.addAttribute("user", userDto);
        return "registration";
    }

    @PostMapping("/user/registration")
    public ModelAndView registerUserAccount(@ModelAttribute("user") @Valid final UserDto userDto,
            final HttpServletRequest request, final Errors errors) {

        registrationUseCase.registerNewUserAccount(userDto);
        return new ModelAndView("successRegister", "user", userDto);
    }

    @GetMapping("/login")
    public ModelAndView login(final HttpServletRequest request, final ModelMap model,
            @RequestParam("messageKey") final Optional<String> messageKey,
            @RequestParam("error") final Optional<String> error) {
        UserDto userDto = UserDto.builder()
                .build();
        model.addAttribute("user", userDto);
        Locale locale = request.getLocale();
        model.addAttribute("lang", locale.getLanguage());
        messageKey.ifPresent(key -> {
            String message = messages.getMessage(key, null, locale);
            model.addAttribute("message", message);
        });

        error.ifPresent(e -> model.addAttribute("error", e));

        return new ModelAndView("login", model);
    }

}
