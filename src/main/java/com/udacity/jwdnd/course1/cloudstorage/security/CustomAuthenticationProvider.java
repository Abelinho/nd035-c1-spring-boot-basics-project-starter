package com.udacity.jwdnd.course1.cloudstorage.security;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    // Your data access service to interact with the database
    // @Autowired
    // private UserService userService;

    //@Autowired
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // Retrieve user details from your database
        // User user = userService.getUserByUsername(username);

        // For demonstration purposes, let's hardcode a user
        User user = new User("username", passwordEncoder.encode("password"), new ArrayList<>());

        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            // Add user roles/authorities as needed
            // authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
            return new UsernamePasswordAuthenticationToken(username, password, authorities);
        } else {
            throw new AuthenticationException("Invalid username or password") {
            };

        //return null;
      }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
       // return false;
    }
}
