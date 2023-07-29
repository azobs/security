package com.c2psi.security.demo;

import org.springframework.web.bind.annotation.*;
/***************************************
 * Pour la demonstration des permissions
 * 29-07-2023
 */
@RestController
@RequestMapping("/api/v1/manager")
public class ManagementController {
    @GetMapping
    public String get(){
        return "GET :: management controller";
    }

    @PostMapping
    public String post(){
        return "POST :: management controller";
    }

    @PutMapping
    public String put(){
        return "PUT :: management controller";
    }

    @DeleteMapping
    public String delete(){
        return "DELETE :: management controller";
    }
}
