package com.c2psi.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //System.err.println("Lancement du filtre JwtAuthenticationFilter avec sa methode doFilterInternal");
        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String userEmail = null;
        //System.err.println("authHeader "+ authHeader);
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            //System.err.println("le authHeader vaut "+authHeader+" et !authHeader.startsWith(\"Bearer \") retourne "+!authHeader.startsWith("Bearer "));
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        //System.err.println("On recupere donc le jwt =="+jwt+" et le userEmail == "+userEmail);

//        if(authHeader != null && authHeader.startsWith("Bearer ")){
//            jwt = authHeader.substring(7);
//            //System.err.println("jwt == "+jwt);
//            userEmail = jwtService.extractUsername(jwt);
//            //System.err.println("userEmail == "+userEmail);
//        }

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            //System.err.println("userEmail == "+userEmail+ " SecurityContextHolder.getContext().getAuthentication() "+SecurityContextHolder.getContext().getAuthentication());
            //System.err.println("On va donc rechercher le User dans la BD");
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //System.err.println("Le user etant trouver on va verifier si le token recuperer l'appartient vraiment et " +"n'est pas encore expire");
            if(jwtService.isTokenValid(jwt, userDetails)){
                //System.err.println("ICI on est sur que le token est valid");
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
                        null,
                        userDetails.getAuthorities());
                //System.err.println("On a donc fabriquer un UsernamePasswordAuthenticationToken "+authToken);
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                //System.err.println("On a set les details de ce UsernamePasswordAuthenticationToken fabrique");
                SecurityContextHolder.getContext().setAuthentication(authToken);
                //System.err.println("On a place ce UsernamePasswordAuthenticationToken fabrique dans le contexte de securite");
            }
            //System.err.println("le filtre JwtAuthenticationFilter a donc fini son travail ");
        }
        //System.err.println("Il laisse donc la requete http continuer sa route ");
        filterChain.doFilter(request, response);
    }
}
