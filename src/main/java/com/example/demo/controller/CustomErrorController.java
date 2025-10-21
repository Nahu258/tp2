package com.example.demo.controller;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.ui.Model;

/**
 * Controlador personalizado de errores
 * Maneja errores de la aplicación de forma amigable
 */
@Controller
public class CustomErrorController implements ErrorController {

    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        
        if (status != null) {
            int statusCode = Integer.parseInt(status.toString());
            
            if (statusCode == HttpStatus.NOT_FOUND.value()) {
                model.addAttribute("errorTitle", "Página no encontrada");
                model.addAttribute("errorMessage", "La página que buscas no existe.");
            } else if (statusCode == HttpStatus.FORBIDDEN.value()) {
                model.addAttribute("errorTitle", "Acceso denegado");
                model.addAttribute("errorMessage", "No tienes permisos para acceder a este recurso.");
            } else if (statusCode == HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                model.addAttribute("errorTitle", "Error del servidor");
                model.addAttribute("errorMessage", "Ha ocurrido un error interno. Por favor, intenta nuevamente.");
            } else {
                model.addAttribute("errorTitle", "Error");
                model.addAttribute("errorMessage", "Ha ocurrido un error inesperado.");
            }
            
            model.addAttribute("statusCode", statusCode);
        }
        
        return "error";
    }
}