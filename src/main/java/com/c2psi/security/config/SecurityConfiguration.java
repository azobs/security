package com.c2psi.security.config;

import com.c2psi.security.userbm.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.c2psi.security.userbm.Permission.*;
import static com.c2psi.security.userbm.Role.*;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
//Ajout du 29-07-2023
/******
 * pour ajouter l'annotation permettant d'indique a spring qu'une partie de la securite a ete
 * decentraliser au niveau des controllers. Sans cette annotation les @PreAuthorize ne seront
 * pas pris en compte par Spring
 *
 * On peut donc centraliser la securite de toutes l'application ici ou alors decentraliser cette
 * securite sur chaque endpoint dans les controllers.
 */
@EnableMethodSecurity
//Fin des ajouts du 29-07-2023
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //System.err.println("Configuration de la securite sur l'application ");
        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()

                //Ajout du 29-07-2023 pour la gestion des permissions sur les endpoint
                //Secure all the management endpoint
                .requestMatchers("/api/v1/management/**").hasAnyRole(Admin.name(), Manager.name())

                //Secure each method on that management endpoint
                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_POST.name(), MANAGER_POST.name())
                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_PUT.name(), MANAGER_PUT.name())
                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

                //About the admin endpoint where only admin can acess
                //.requestMatchers("/api/v1/admin/**").hasRole(Admin.name())

                //Secure each method on that admin endpoint
                /*.requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
                .requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_POST.name())
                .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_PUT.name())
                .requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())*/

                /*****
                 * Les lignes ci-dessus concernant /api/v1/admin/** ajouter le 29-07-2023
                 * seront mise en commentaire pour ajouter plutot obtenir le meme resultat
                 * en decentralisant la securite au niveau des controller en utilisant les
                 * annotations
                 */

                //Fin des ajouts du 29-07-2023
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                //Ajout du 28-07-2023 pour gerer le logout
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext())
                //fin des ajouts du 28-07-2023
                ;
        return http.build();
    }
}
