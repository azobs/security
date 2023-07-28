package com.c2psi.security.config;

import com.c2psi.security.userbm.Role;
import com.c2psi.security.userbm.Userbm;
import com.c2psi.security.userbm.UserbmRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserbmRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        System.out.println("request "+request);
        var userbm = Userbm.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.User)
                .build();
        Userbm userbmSaved = repository.save(userbm);
        var jwtToken = jwtService.generateToken(userbmSaved);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        System.err.println("Dans authenticate email = "+request.getEmail()+ " password ="+request.getPassword());
        String at = authenticationManager.toString();
        System.err.println("authenticationManager "+authenticationManager);
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );
        }
        catch (Exception e){
            e.printStackTrace();
        }
        System.err.println("Dans authenticate mais pendant la generation de la reponse");
        Optional<Userbm> optionalUserbm = repository.findByEmail(request.getEmail());
        if(optionalUserbm.isEmpty()){
            throw new UsernameNotFoundException("userEmail or Password incorrect");
        }
        var jwtToken = jwtService.generateToken(optionalUserbm.get());
        System.out.println("le jwt generate lors de l'authenticate "+jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
