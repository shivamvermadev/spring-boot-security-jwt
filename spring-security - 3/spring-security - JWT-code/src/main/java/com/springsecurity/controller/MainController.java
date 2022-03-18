package com.springsecurity.controller;

import com.springsecurity.config.CustomUserDetailsService;
import com.springsecurity.config.JwtUtil;
import com.springsecurity.model.AuthenticationRequest;
import com.springsecurity.model.AuthenticationResponse;
import com.springsecurity.model.UserDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder bcryptEncoder;

    public MainController(AuthenticationManager authenticationManager, CustomUserDetailsService customUserDetailsService, JwtUtil jwtUtil, PasswordEncoder bcryptEncoder) {
        this.authenticationManager = authenticationManager;
        this.customUserDetailsService = customUserDetailsService;
        this.jwtUtil = jwtUtil;
        this.bcryptEncoder = bcryptEncoder;
    }

    @GetMapping("/helloadmin")
    public String helloAdmin() {
        return "hello admin";
    }

    @GetMapping("/hellouser")
    public String helloUser() {
        return "hello user";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        }
        catch (DisabledException e) {
            throw new Exception("User is disabled", e);
        }
        catch (BadCredentialsException e) {
            throw new Exception("Bad credentials", e);
        }
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final String token = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(token));
    }

    @PostMapping("/register")
    public ResponseEntity<?> saveUser(@RequestBody UserDTO userDTO) {
        String password = userDTO.getPassword();
        userDTO.setPassword(bcryptEncoder.encode(password));
        return ResponseEntity.ok(customUserDetailsService.save(userDTO));
    }
}
