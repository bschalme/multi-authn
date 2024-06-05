package com.example.multiauthn.adapter.in.web.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public ModelAndView userHome(Authentication authn) {
        ModelMap modelMap = new ModelMap("user", authn.getPrincipal());
        return new ModelAndView("admin", modelMap);
    }
}
