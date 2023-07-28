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
        final String authHeader = request.getHeader("Authorization");
        String jwt = null;
        String userEmail = null;
        System.err.println("authHeader "+ authHeader);
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            System.err.println("ici2");
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        System.err.println("jwt == "+jwt);
        userEmail = jwtService.extractUsername(jwt);
        System.err.println("userEmail == "+userEmail);

//        if(authHeader != null && authHeader.startsWith("Bearer ")){
//            jwt = authHeader.substring(7);
//            System.err.println("jwt == "+jwt);
//            userEmail = jwtService.extractUsername(jwt);
//            System.err.println("userEmail == "+userEmail);
//        }

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            System.out.println("userEmail == "+userEmail+ " SecurityContextHolder.getContext().getAuthentication() "+SecurityContextHolder.getContext().getAuthentication());
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            if(jwtService.isTokenValid(jwt, userDetails)){
                System.err.println("ICI on est sur que le token est valid");
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails,
                        null,
                        userDetails.getAuthorities());
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            System.err.println("suite du filtre "+ jwtService.isTokenValid(jwt, userDetails));
        }
        filterChain.doFilter(request, response);
    }
}
