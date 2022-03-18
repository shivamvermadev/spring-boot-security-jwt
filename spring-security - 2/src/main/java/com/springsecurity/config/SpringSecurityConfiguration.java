package com.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService userDetailService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final CustomJwtAuthenticationFilter customJwtAuthenticationFilter;

    @Autowired
    public SpringSecurityConfiguration(CustomUserDetailsService userDetailService,
                                       JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                                       CustomJwtAuthenticationFilter customJwtAuthenticationFilter) {
        this.userDetailService = userDetailService;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.customJwtAuthenticationFilter = customJwtAuthenticationFilter;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailService).passwordEncoder(passwordEncoder());
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/helloadmin").hasRole("ADMIN")
                .antMatchers("/hellouser").hasAnyRole("ADMIN", "USER")
                .antMatchers("/authenticate", "/register").permitAll().anyRequest().authenticated()
                .and().exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(customJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
