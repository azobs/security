package com.c2psi.security.demo;

import org.springframework.web.bind.annotation.*;

/***************************************
 * Pour la demonstration des permissions
 * 29-07-2023
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    @GetMapping
    public String get(){
        return "GET :: admin controller";
    }

    @PostMapping
    public String post(){
        return "POST :: admin controller";
    }

    @PutMapping
    public String put(){
        return "PUT :: admin controller";
    }

    @DeleteMapping
    public String delete(){
        return "DELETE :: admin controller";
    }
    //
}
