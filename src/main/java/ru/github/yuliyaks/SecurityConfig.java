package ru.github.yuliyaks;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                    .antMatchers("/private-data").hasRole("ADMIN")
                    .antMatchers("/public-data").authenticated()
                .and()
                    .formLogin()
                .and()
                    .logout()
                    .logoutSuccessUrl("/home") // Указать URL-адрес для перенаправления после выхода из системы
                    .invalidateHttpSession(true) // Аннулировать HTTP-сессию
                    .deleteCookies("JSESSIONID") // Удалить файл cookie JSESSIONID
                .and()
                    .csrf().disable(); // Отключить CSRF
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}password").roles("USER")
                .and()
                .withUser("admin").password("{noop}password").roles("ADMIN");
    }

}








