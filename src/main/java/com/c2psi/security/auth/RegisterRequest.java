package com.c2psi.security.auth;

import com.c2psi.security.userbm.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String password;
    //Ajout du 29-07-2023
    private Role role;
    //Fin des ajouts du 29-07-2023
}
