package com.example.demo.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handler personalizado para manejar errores de autenticación
 * Distingue entre errores de OAuth2 y login tradicional
 */
@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, 
                                       HttpServletResponse response,
                                       AuthenticationException exception) throws IOException, ServletException {
        
        String errorMessage = "error=true";
        
        // Detectar el tipo de error
        if (exception.getMessage().contains("Bad credentials")) {
            errorMessage = "error=credentials";
        } else if (exception.getMessage().contains("User not found")) {
            errorMessage = "error=notfound";
        }
        
        setDefaultFailureUrl("/login?" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }
}