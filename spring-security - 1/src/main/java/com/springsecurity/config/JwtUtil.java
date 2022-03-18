package com.springsecurity.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class JwtUtil {

    private String secretKey;
    private int jwtExpirationInMs;

    @Value("${jwt.secret}")
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    @Value("${jwt.jwtExpirationInMs}")
    public void setJwtExpirationInMs(int jwtExpirationInMs) {
        this.jwtExpirationInMs = jwtExpirationInMs;
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        Collection<? extends GrantedAuthority> roles = userDetails.getAuthorities();
        if (roles.contains(new SimpleGrantedAuthority("ROLE_ADMIN"))) {
            claims.put("isAdmin", true);
        }
        if (roles.contains(new SimpleGrantedAuthority("ROLE_USER"))) {
            claims.put("isUser", true);
        }

        return doGenerateToken(claims, userDetails.getUsername());
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs)).signWith(SignatureAlgorithm.HS512, secretKey).compact();
    }

    public boolean validateToken(String authToken) {
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken); // if exception is thrown then the token is invalid
            return true;
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new BadCredentialsException("Invalid credentials", e);
        } catch (ExpiredJwtException e) {
            throw e;
        }
    }

    public String getUserName(String authToken) {
        Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken).getBody();
        return claims.getSubject(); //returns the username that is stored while creating token
    }

    public List<SimpleGrantedAuthority> getRolesFromToken(String authToken) {
        List<SimpleGrantedAuthority> roles = null;
        Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken).getBody();
        Boolean isAdmin = claims.get("isAdmin", Boolean.class);
        Boolean isUser = claims.get("isUser", Boolean.class);

        if (isAdmin != null && isAdmin == true) {
            roles = Collections.singletonList(new SimpleGrantedAuthority("ROLE_ADMIN"));
        }
        if (isUser != null && isUser == true) {
            roles = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        }
        return roles;
    }
}
