package com.c2psi.security.auth;

import com.c2psi.security.config.JwtService;
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
        //System.err.println("request "+request);
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
        //System.err.println("Lancement de la fonction authenticate du service AuthenticationService ");
        //System.err.println("Et dans authenticate on a  email = "+request.getEmail()+ " et password ="+request.getPassword());
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
        //System.err.println("Apres l'authentification grace a l'authenticationManager  ");
        Optional<Userbm> optionalUserbm = repository.findByEmail(request.getEmail());
        if(optionalUserbm.isEmpty()){
            throw new UsernameNotFoundException("userEmail or Password incorrect");
        }
        var jwtToken = jwtService.generateToken(optionalUserbm.get());
        //System.err.println("le jwt genere apres l'authentication"+jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
