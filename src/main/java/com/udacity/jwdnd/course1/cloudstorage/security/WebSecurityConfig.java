package com.udacity.jwdnd.course1.cloudstorage.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig  extends WebSecurityConfigurerAdapter {

@Autowired
CustomAuthenticationProvider customAuthenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {//.hasRole("USER")
        http.authorizeRequests().antMatchers("/public/**","/login","/signup").permitAll()
                .anyRequest().authenticated()
                .and()
                // Possibly more configuration ...
                .formLogin() // enable form based log in
                .loginPage("/login")
                // set permitAll for all URLs associated with Form Login
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")
                .permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(customAuthenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .antMatchers("/resources/**","/images/**", "/js/**", "/webjars/**");
    }
}
