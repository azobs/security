package com.c2psi.security;

import com.c2psi.security.auth.AuthenticationService;
import com.c2psi.security.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import static com.c2psi.security.userbm.Role.*;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	//Ajout du 29-07-2023 pour la gestion des roles et permissions
	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService authenticationService){
		return args -> {
			var adminRequest = RegisterRequest.builder()
					.firstName("admin")
					.lastName("admin")
					.email("admin@gmail.com")
					.password("password")
					.role(Admin)
					.build();
			System.out.println("Admin token: "+ authenticationService.register(adminRequest).getToken());

			var managerRequest = RegisterRequest.builder()
					.firstName("manager")
					.lastName("manager")
					.email("manager@gmail.com")
					.password("password")
					.role(Manager)
					.build();
			System.out.println("Manager token: "+ authenticationService.register(managerRequest).getToken());
		};
	}
	//Fin des ajouts du 29-07-2023

}
