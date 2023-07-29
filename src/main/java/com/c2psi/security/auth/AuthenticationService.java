package com.c2psi.security.auth;

import com.c2psi.security.config.JwtService;
import com.c2psi.security.token.Token;
import com.c2psi.security.token.TokenRepository;
import com.c2psi.security.token.TokenType;
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

    //Declaration du 28-07-2023
    private final TokenRepository tokenRepository;
    //fin des declaration du 28-07-2023
    public AuthenticationResponse register(RegisterRequest request) {
        //System.err.println("request "+request);
        var userbm = Userbm.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                //Ajout du 29-07-2023 pour la gestion des roles et permissions
                //La ligne .role(Role.User) a ete mise en commentaire et remplacer par la suivante
                .role(request.getRole())
                //fin des ajouts du 29-07-2023
                //.role(Role.User)
                .build();
        var userbmSaved = repository.save(userbm);
        var jwtToken = jwtService.generateToken(userbmSaved);
        //Adding line 28-07-2023
        saveUserToken(userbmSaved, jwtToken);
        //End of adding line of 28-07-2023
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void revokeAllExistingTokenListofUser(Userbm userbm){
        var validUserTokenList = tokenRepository.findAllValidTokenListByUser(userbm.getId());
        if(validUserTokenList.isEmpty()) return;
        validUserTokenList.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokenList);
    }

    private void saveUserToken(Userbm userbm, String jwtToken) {
        var token = Token.builder()
                .userbm(userbm)
                .token(jwtToken)
                .tokenType(TokenType.Bearer)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
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
        revokeAllExistingTokenListofUser(optionalUserbm.get());
        saveUserToken(optionalUserbm.get(), jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
