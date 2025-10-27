package com.example.demo.controller;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.service.AuditoriaService;
import com.example.demo.service.SistemaLogin;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
public class DashboardController {

    @Autowired
    private SistemaLogin sistemaLogin;

    @Autowired
    private AuditoriaService auditoriaService;

    @GetMapping("/dashboard")
    public String mostrarDashboard(Authentication authentication, Model model, HttpServletRequest request) {
        String nombreUsuario = authentication.getName();
        
        // Buscar usuario en BD
        Optional<Usuario> usuarioOpt = sistemaLogin.obtenerUsuarioPorNombre(nombreUsuario);
        
        if (usuarioOpt.isEmpty()) {
            return "redirect:/login?error=usuario_no_encontrado";
        }
        
        Usuario usuario = usuarioOpt.get();
        
        // Registrar acceso al dashboard
        auditoriaService.registrarEvento(
            nombreUsuario,
            "ACCESO_DASHBOARD",
            "/dashboard",
            request
        );
        
        // Datos básicos del usuario
        model.addAttribute("usuario", usuario);
        model.addAttribute("nombreRol", usuario.getRol().nombre);
        
        // Obtener permisos del usuario
        List<String> permisos = usuario.getRol().permisos != null
            ? usuario.getRol().permisos.stream()
                .map(p -> p.nombre)
                .collect(Collectors.toList())
            : List.of();
        model.addAttribute("permisos", permisos);
        
        // Autorización
        String autorizacion = sistemaLogin.autorizar(usuario);
        model.addAttribute("autorizacion", autorizacion);
        
        // DATOS PARA ADMINISTRADORES Y SUPERVISORES
        String nombreRol = usuario.getRol().nombre;
        if (nombreRol.equals("Administrador del Sistema") || nombreRol.equals("Supervisor")) {
            
            // Obtener últimos 10 eventos del sistema
            List<Auditoria> ultimosEventos = auditoriaService.obtenerEventosDeHoy();
            if (ultimosEventos.size() > 10) {
                ultimosEventos = ultimosEventos.subList(0, 10);
            }
            model.addAttribute("ultimosEventos", ultimosEventos);
            
            // Estadísticas
            model.addAttribute("eventosHoy", auditoriaService.obtenerEventosDeHoy().size());
            model.addAttribute("totalEventos", auditoriaService.obtenerTodosLosEventos(0, 1).getTotalElements());
            model.addAttribute("usuariosActivos", sistemaLogin.obtenerTodosLosUsuarios().size());
        }
        
        // DATOS SOLO PARA ADMINISTRADORES
        if (nombreRol.equals("Administrador del Sistema")) {
            List<Usuario> todosLosUsuarios = sistemaLogin.obtenerTodosLosUsuarios();
            List<Rol> todosLosRoles = sistemaLogin.obtenerTodosLosRoles();
            
            model.addAttribute("todosLosUsuarios", todosLosUsuarios);
            model.addAttribute("todosLosRoles", todosLosRoles);
        }
        
        return "dashboard";
    }
}
