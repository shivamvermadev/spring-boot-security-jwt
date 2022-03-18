package com.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/helloadmin")
    public String helloAdmin() {
        return "hello admin";
    }

    @GetMapping("/hellouser")
    public String helloUser() {
        return "hello user";
    }
}
