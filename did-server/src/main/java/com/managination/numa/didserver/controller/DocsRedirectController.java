package com.managination.numa.didserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Redirect controller that maps the legacy {@code /docs} path to the Springdoc
 * Swagger UI page at {@code /swagger-ui/index.html}.
 */
@Controller
public class DocsRedirectController {

    /**
     * Redirects {@code /docs} to the Springdoc-powered Swagger UI.
     *
     * @return a redirect view to {@code /swagger-ui/index.html}
     */
    @GetMapping("/docs")
    public String docs() {
        return "redirect:/swagger-ui/index.html";
    }
}
