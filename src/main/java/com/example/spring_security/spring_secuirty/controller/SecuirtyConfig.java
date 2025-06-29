package com.example.spring_security.spring_secuirty.controller;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class SecuirtyConfig {

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("pankaj")
                .password("pankaj")
                .roles("ADMIN")
                .build();

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("pawan")
                .password("pawan")
                .roles("USER")
                .build();

        InMemoryUserDetailsManager inMemoryUserDetailsService = new InMemoryUserDetailsManager(user1,user2);

        return inMemoryUserDetailsService;

    }
}
