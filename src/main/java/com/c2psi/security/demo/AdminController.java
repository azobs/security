package com.c2psi.security.demo;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/***************************************
 * Pour la demonstration des permissions
 * 29-07-2023
 */
@RestController
@RequestMapping("/api/v1/admin")
//Ajout du 29-07-2023 pour gerer la securite et obtenir le meme resultat que celui obtenu en passant par la classe de configuration
@PreAuthorize("hasRole('Admin')")
//Fin des ajouts du 29-07-2023
public class AdminController {
    @GetMapping
    //Ajout du 29-07-2023 pour gerer la securite et obtenir le meme resultat que celui obtenu en passant par la classe de configuration
    @PreAuthorize("hasAuthority('admin:Read')") //admin:Read est le nom de ADMIN_READ dans la classe Permission
    //Fin des ajouts du 29-07-2023
    public String get(){
        return "GET :: admin controller";
    }

    @PostMapping
    //Ajout du 29-07-2023 pour gerer la securite et obtenir le meme resultat que celui obtenu en passant par la classe de configuration
    @PreAuthorize("hasAuthority('admin:Create')") //admin:Create est le nom de ADMIN_POST dans la classe Permission
    //Fin des ajouts du 29-07-2023
    public String post(){
        return "POST :: admin controller";
    }

    @PutMapping
    //Ajout du 29-07-2023 pour gerer la securite et obtenir le meme resultat que celui obtenu en passant par la classe de configuration
    @PreAuthorize("hasAuthority('admin:Update')") //admin:Update est le nom de ADMIN_PUT dans la classe Permission
    //Fin des ajouts du 29-07-2023
    public String put(){
        return "PUT :: admin controller";
    }

    @DeleteMapping
    //Ajout du 29-07-2023 pour gerer la securite et obtenir le meme resultat que celui obtenu en passant par la classe de configuration
    @PreAuthorize("hasAuthority('admin:Delete')") //admin:Read est le nom de ADMIN_DELETE dans la classe Permission
    //Fin des ajouts du 29-07-2023
    public String delete(){
        return "DELETE :: admin controller";
    }
    //
}
