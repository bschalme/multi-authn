package com.example.multiauthn.adapter.in.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoggedOutController {

    @GetMapping("/loggedout")
    public String home() {
        return "loggedout";
    }

}
