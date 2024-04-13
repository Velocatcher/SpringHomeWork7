package ru.github.yuliyaks;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    // Домашняя страница
    @GetMapping("/home")
    public String home() {
        return "home";
    }

    // Приватная страница
    @GetMapping("/private-data")
    public String privateData() {
        return "private-data";
    }

    // Публичная страница
    @GetMapping("/public-data")
    public String publicData() {
        return "public-data";
    }

    // Страница аутентификации
    @GetMapping("/login")
    public String login() {
        return "login";
    }

}
