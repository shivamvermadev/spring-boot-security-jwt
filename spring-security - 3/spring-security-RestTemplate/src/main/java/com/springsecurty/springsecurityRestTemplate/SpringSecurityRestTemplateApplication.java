package com.springsecurty.springsecurityRestTemplate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class SpringSecurityRestTemplateApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityRestTemplateApplication.class, args);
	}

	@Bean
	public RestTemplate getRestTemplate() {
		return new RestTemplate();
	}
}
