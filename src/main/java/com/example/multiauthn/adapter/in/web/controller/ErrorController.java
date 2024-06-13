package com.example.multiauthn.adapter.in.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ErrorController {

    @GetMapping("/accessDenied")
    public String accessDenied() {
        return "accessDenied";
    }

    @GetMapping("/noRolesAssigned")
    public String noRolesAssigned() {
        return "noRolesAssigned";
    }
}
