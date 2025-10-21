package com.example.demo.controller;

import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.service.SistemaLogin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;
import java.util.Optional;
import java.util.Map;

/**
 * Controlador de Autenticación
 * Maneja el flujo de login según el pseudocódigo del PDF
 * Adaptado para trabajar con Spring Security y OAuth2
 */
@Controller
public class AuthController {

    @Autowired
    private SistemaLogin sistema;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @GetMapping("/")
    public String index() {
        return "redirect:/login";
    }

    /**
     * Página de login
     * Spring Security maneja automáticamente el POST a /login
     * pero nosotros mostramos la vista
     */
    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    /**
     * Dashboard - Accesible después de autenticación exitosa
     * Obtiene el usuario autenticado de Spring Security
     * Soporta tanto login tradicional como OAuth2
     */
    @GetMapping("/dashboard")
    public String dashboard(Authentication authentication,
                           @AuthenticationPrincipal OAuth2User oauth2User,
                           Model model) {
        
        Usuario usuario = null;
        
        // Determinar si es login tradicional o OAuth2
        if (oauth2User != null) {
            // Usuario autenticado con OAuth2
            String email = oauth2User.getAttribute("email");
            String login = oauth2User.getAttribute("login"); // para GitHub
            
            // Determinar el proveedor OAuth2
            String provider = "google"; // valor por defecto
            if (login != null && email == null) {
                provider = "github";
            }
            
            // Construir username
            String username = provider + "_" + (email != null ? email : login);
            
            // Buscar usuario en BD
            Optional<Usuario> usuarioOpt = sistema.obtenerUsuarioPorNombre(username);
            if (usuarioOpt.isPresent()) {
                usuario = usuarioOpt.get();
            } else {
                // Si el usuario OAuth2 no existe en BD, redirigir con error
                model.addAttribute("error", "Usuario OAuth2 no encontrado en el sistema");
                return "redirect:/login?error=oauth";
            }
        } else if (authentication != null) {
            // Usuario autenticado con login tradicional
            String username = authentication.getName();
            Optional<Usuario> usuarioOpt = sistema.obtenerUsuarioPorNombre(username);
            if (usuarioOpt.isPresent()) {
                usuario = usuarioOpt.get();
            } else {
                return "redirect:/login?error=notfound";
            }
        }
        
        if (usuario == null) {
            return "redirect:/login";
        }

        // sistema.autorizar(usuario) - según consigna
        model.addAttribute("usuario", usuario);
        model.addAttribute("autorizacion", sistema.autorizar(usuario));
        model.addAttribute("nombreRol", usuario.getRol().nombre);
        model.addAttribute("permisos", usuario.getRol().getNombresPermisos());
        
        // Si es administrador, cargar lista de usuarios y roles
        if ("Administrador del Sistema".equals(usuario.getRol().nombre)) {
            List<Usuario> todosLosUsuarios = sistema.obtenerTodosLosUsuarios();
            List<Rol> todosLosRoles = sistema.obtenerTodosLosRoles();
            model.addAttribute("todosLosUsuarios", todosLosUsuarios);
            model.addAttribute("todosLosRoles", todosLosRoles);
        }
        
        return "dashboard";
    }

    /**
     * Logout es manejado automáticamente por Spring Security
     * Configurado en SecurityConfig para redirigir a /login?logout=true
     */

    @GetMapping("/registro")
    public String registroPage() {
        return "registro";
    }

    /**
     * Registrar usuario según consigna:
     * sistema.registrarUsuario(nuevo Usuario(nombre, clave, rol))
     * 
     * Lógica de asignación de roles:
     * - Si nombreUsuario es "admin": Administrador del Sistema
     * - Cualquier otro caso: Personal (rol por defecto)
     * 
     * IMPORTANTE: Hashea la contraseña con BCrypt antes de guardar
     */
    @PostMapping("/registro")
    public String registro(@RequestParam String nombreUsuario,
                          @RequestParam String clave,
                          Model model) {
        
        // Validar que los campos no estén vacíos
        if (nombreUsuario == null || nombreUsuario.trim().isEmpty()) {
            model.addAttribute("error", "El nombre de usuario es requerido");
            return "registro";
        }
        
        if (clave == null || clave.trim().isEmpty()) {
            model.addAttribute("error", "La contraseña es requerida");
            return "registro";
        }
        
        // Determinar el rol según el nombre de usuario
        String rolNombre;
        if ("admin".equalsIgnoreCase(nombreUsuario.trim())) {
            rolNombre = "Administrador del Sistema";
        } else {
            rolNombre = "Personal";
        }
        
        Optional<Rol> rolOpt = sistema.obtenerRolPorNombre(rolNombre);
        
        if (rolOpt.isEmpty()) {
            model.addAttribute("error", "Error en la asignación de rol");
            return "registro";
        }
        
        // IMPORTANTE: Hashear la contraseña con BCrypt
        String claveHasheada = passwordEncoder.encode(clave);
        
        // nuevo Usuario(nombre, claveHasheada, rol)
        Usuario nuevoUsuario = new Usuario(nombreUsuario.trim(), claveHasheada, rolOpt.get());
        
        // sistema.registrarUsuario(usuario)
        boolean registrado = sistema.registrarUsuario(nuevoUsuario);
        
        if (registrado) {
            model.addAttribute("mensaje", "Usuario registrado exitosamente. Inicia sesión.");
            return "login";
        } else {
            model.addAttribute("error", "El nombre de usuario ya existe");
            return "registro";
        }
    }

    /**
     * Actualizar rol de un usuario (solo para administradores)
     * Spring Security verifica los permisos automáticamente
     */
    @PostMapping("/admin/actualizar-roles")
    public String actualizarRol(@RequestParam Long userId,
                               @RequestParam Map<String, String> allParams,
                               Authentication authentication,
                               Model model) {
        
        // Verificar que haya una autenticación válida
        if (authentication == null) {
            return "redirect:/login";
        }
        
        // Obtener usuario actual desde Spring Security
        String username = authentication.getName();
        Optional<Usuario> usuarioActualOpt = sistema.obtenerUsuarioPorNombre(username);
        
        if (usuarioActualOpt.isEmpty()) {
            return "redirect:/login";
        }
        
        Usuario usuarioActual = usuarioActualOpt.get();
        
        // Verificar que el usuario actual sea administrador
        if (!"Administrador del Sistema".equals(usuarioActual.getRol().nombre)) {
            model.addAttribute("error", "No tienes permisos para realizar esta acción");
            return "redirect:/dashboard";
        }

        // Obtener el valor del parámetro dinámico rol_X
        String paramName = "rol_" + userId;
        String nuevoRolIdStr = allParams.get(paramName);
        
        if (nuevoRolIdStr == null || nuevoRolIdStr.trim().isEmpty()) {
            model.addAttribute("error", "Rol no especificado");
            // Recargar datos
            cargarDatosAdmin(model, usuarioActual);
            return "dashboard";
        }
        
        try {
            Long nuevoRolId = Long.parseLong(nuevoRolIdStr);
            boolean actualizado = sistema.actualizarRolUsuario(userId, nuevoRolId);
            
            if (actualizado) {
                model.addAttribute("mensaje", "Rol actualizado exitosamente");
            } else {
                model.addAttribute("error", "No se pudo actualizar el rol");
            }
        } catch (NumberFormatException e) {
            model.addAttribute("error", "ID de rol inválido");
        } catch (Exception e) {
            model.addAttribute("error", "Error al actualizar el rol: " + e.getMessage());
        }
        
        // Recargar datos para el dashboard
        cargarDatosAdmin(model, usuarioActual);
        
        return "dashboard";
    }
    
    /**
     * Método auxiliar para cargar datos del administrador en el dashboard
     */
    private void cargarDatosAdmin(Model model, Usuario usuarioActual) {
        model.addAttribute("usuario", usuarioActual);
        model.addAttribute("autorizacion", sistema.autorizar(usuarioActual));
        model.addAttribute("nombreRol", usuarioActual.getRol().nombre);
        model.addAttribute("permisos", usuarioActual.getRol().getNombresPermisos());
        model.addAttribute("todosLosUsuarios", sistema.obtenerTodosLosUsuarios());
        model.addAttribute("todosLosRoles", sistema.obtenerTodosLosRoles());
    }
}