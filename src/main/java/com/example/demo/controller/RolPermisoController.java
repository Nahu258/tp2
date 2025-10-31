package com.example.demo.controller;

import com.example.demo.dto.RolDTO;
import com.example.demo.model.Permiso;
import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.service.AuditoriaService;
import com.example.demo.service.RolPermisoService;
import com.example.demo.service.SistemaLogin;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.transaction.annotation.Transactional;


/**
 * Controller para gestión de Roles y Permisos
 * Solo accesible por Administradores del Sistema
 */
@Controller
@RequestMapping("/admin/roles-permisos")
@PreAuthorize("hasRole('ADMIN')")
public class RolPermisoController {

    @Autowired
    private RolPermisoService rolPermisoService;

    @Autowired
    private SistemaLogin sistemaLogin;

    @Autowired
    private AuditoriaService auditoriaService;

    /**
     * Vista principal de gestión
    */
    @GetMapping
    public String verGestion(Authentication authentication, Model model, HttpServletRequest request) {
        try {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "ACCESO_GESTION_ROLES",
                "/admin/roles-permisos",
                request
            );
        
            Optional<Usuario> usuarioOpt = sistemaLogin.obtenerUsuarioPorNombre(authentication.getName());
            if (usuarioOpt.isEmpty()) {
                return "redirect:/login";
            }
        
            Usuario usuario = usuarioOpt.get();
            
            // Obtener DTOs y datos necesarios
            List<RolDTO> rolesDTO = rolPermisoService.obtenerTodosLosRolesDTO();
            List<Permiso> permisos = rolPermisoService.obtenerTodosLosPermisos();
        
            model.addAttribute("usuario", usuario);
            model.addAttribute("nombreRol", usuario.getRol().nombre);
            model.addAttribute("roles", rolesDTO); // ← CAMBIAR: Ya no es "rolesDTO", es "roles"
            model.addAttribute("permisos", permisos);
        
            return "roles-permisos";
            
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("❌ ERROR: " + e.getMessage());
            e.printStackTrace();
            model.addAttribute("error", "Error al cargar roles: " + e.getMessage());
            return "redirect:/dashboard?error=No se pudo cargar la gestión de roles";
        }
    }

    // ==================== ROLES ====================

    /**
     * Crear nuevo rol
     */
    @PostMapping("/roles/crear")
    public String crearRol(
            @RequestParam String nombre,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Rol nuevoRol = rolPermisoService.crearRol(nombre);

            auditoriaService.registrarEvento(
                authentication.getName(),
                "CREAR_ROL",
                "/admin/roles-permisos/roles/crear",
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Rol creado: " + nombre
            );

            redirectAttributes.addFlashAttribute("mensaje", "Rol '" + nombre + "' creado exitosamente");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "CREAR_ROL",
                "/admin/roles-permisos/roles/crear",
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }

    /**
     * Actualizar nombre de rol
     */
    @PostMapping("/roles/actualizar/{id}")
    public String actualizarRol(
            @PathVariable Long id,
            @RequestParam String nombre,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Rol rol = rolPermisoService.actualizarRol(id, nombre);

            auditoriaService.registrarEvento(
                authentication.getName(),
                "ACTUALIZAR_ROL",
                "/admin/roles-permisos/roles/actualizar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Rol actualizado: " + nombre
            );

            redirectAttributes.addFlashAttribute("mensaje", "Rol actualizado exitosamente");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "ACTUALIZAR_ROL",
                "/admin/roles-permisos/roles/actualizar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }

    /**
     * Eliminar rol
     */
    @PostMapping("/roles/eliminar/{id}")
    public String eliminarRol(
            @PathVariable Long id,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Optional<Rol> rolOpt = rolPermisoService.obtenerRolPorId(id);
            String nombreRol = rolOpt.map(r -> r.nombre).orElse("Desconocido");

            rolPermisoService.eliminarRol(id);

            auditoriaService.registrarEvento(
                authentication.getName(),
                "ELIMINAR_ROL",
                "/admin/roles-permisos/roles/eliminar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Rol eliminado: " + nombreRol
            );

            redirectAttributes.addFlashAttribute("mensaje", "Rol eliminado exitosamente");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "ELIMINAR_ROL",
                "/admin/roles-permisos/roles/eliminar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }

    // ==================== PERMISOS ====================

    /**
     * Crear nuevo permiso
     */
    @PostMapping("/permisos/crear")
    public String crearPermiso(
            @RequestParam String nombre,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Permiso nuevoPermiso = rolPermisoService.crearPermiso(nombre);

            auditoriaService.registrarEvento(
                authentication.getName(),
                "CREAR_PERMISO",
                "/admin/roles-permisos/permisos/crear",
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Permiso creado: " + nombre
            );

            redirectAttributes.addFlashAttribute("mensaje", "Permiso '" + nombre + "' creado exitosamente");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "CREAR_PERMISO",
                "/admin/roles-permisos/permisos/crear",
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }

    /**
     * Eliminar permiso
     */
    @PostMapping("/permisos/eliminar/{id}")
    public String eliminarPermiso(
            @PathVariable Long id,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Optional<Permiso> permisoOpt = rolPermisoService.obtenerPermisoPorId(id);
            String nombrePermiso = permisoOpt.map(p -> p.nombre).orElse("Desconocido");

            rolPermisoService.eliminarPermiso(id);

            auditoriaService.registrarEvento(
                authentication.getName(),
                "ELIMINAR_PERMISO",
                "/admin/roles-permisos/permisos/eliminar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Permiso eliminado: " + nombrePermiso
            );

            redirectAttributes.addFlashAttribute("mensaje", "Permiso eliminado exitosamente");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "ELIMINAR_PERMISO",
                "/admin/roles-permisos/permisos/eliminar/" + id,
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }

    // ==================== ASIGNACIÓN ====================

    /**
     * Asignar permisos a un rol
     */
    @PostMapping("/roles/{rolId}/permisos")
    public String asignarPermisos(
            @PathVariable Long rolId,
            @RequestParam(required = false) List<Long> permisos,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            Set<Long> permisosSet = permisos != null ? new HashSet<>(permisos) : new HashSet<>();
            Rol rol = rolPermisoService.asignarPermisosARol(rolId, permisosSet);

            String permisosStr = rol.permisos.stream()
                .map(p -> p.nombre)
                .collect(Collectors.joining(", "));

            auditoriaService.registrarEvento(
                authentication.getName(),
                "ASIGNAR_PERMISOS",
                "/admin/roles-permisos/roles/" + rolId + "/permisos",
                request,
                com.example.demo.model.Auditoria.Resultado.EXITOSO,
                "Permisos asignados a '" + rol.nombre + "': " + permisosStr
            );

            redirectAttributes.addFlashAttribute("mensaje", 
                "Permisos actualizados para el rol '" + rol.nombre + "'");
        } catch (Exception e) {
            auditoriaService.registrarEvento(
                authentication.getName(),
                "ASIGNAR_PERMISOS",
                "/admin/roles-permisos/roles/" + rolId + "/permisos",
                request,
                com.example.demo.model.Auditoria.Resultado.FALLIDO,
                "Error: " + e.getMessage()
            );

            redirectAttributes.addFlashAttribute("error", e.getMessage());
        }

        return "redirect:/admin/roles-permisos";
    }
}