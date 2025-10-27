package com.example.demo.controller;

import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.service.AuditoriaService;
import com.example.demo.service.SistemaLogin;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;
import java.util.Optional;

@Controller
public class AdminController {

    @Autowired
    private SistemaLogin sistemaLogin;

    @Autowired
    private AuditoriaService auditoriaService;

    /**
     * Endpoint para actualizar roles de usuarios
     * Solo accesible por administradores
     */
    @PostMapping("/admin/actualizar-roles")
    @PreAuthorize("hasRole('ADMIN')")
    public String actualizarRoles(
            @RequestParam Long userId,
            @RequestParam Map<String, String> params,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        try {
            // Buscar el usuario a modificar
            Optional<Usuario> usuarioOpt = sistemaLogin.obtenerUsuarioPorNombre(
                    sistemaLogin.obtenerTodosLosUsuarios().stream()
                            .filter(u -> u.getId().equals(userId))
                            .findFirst()
                            .orElseThrow()
                            .getNombreUsuario()
            );

            if (usuarioOpt.isEmpty()) {
                redirectAttributes.addFlashAttribute("error", "Usuario no encontrado");
                return "redirect:/dashboard";
            }

            Usuario usuarioAModificar = usuarioOpt.get();
            String rolAnterior = usuarioAModificar.getRol().nombre;

            // Buscar el parámetro del nuevo rol (rol_X)
            String paramName = "rol_" + userId;
            String nuevoRolStr = params.get(paramName);

            if (nuevoRolStr == null) {
                redirectAttributes.addFlashAttribute("error", "No se especificó un nuevo rol");
                return "redirect:/dashboard";
            }

            Long nuevoRolId = Long.parseLong(nuevoRolStr);

            // Actualizar el rol
            boolean actualizado = sistemaLogin.actualizarRolUsuario(userId, nuevoRolId);

            if (actualizado) {
                // Obtener el nuevo rol (usando variable final)
                final Long rolIdFinal = nuevoRolId;
                Optional<Rol> nuevoRolOpt = sistemaLogin.obtenerTodosLosRoles().stream()
                        .filter(r -> r.getId().equals(rolIdFinal))
                        .findFirst();

                String rolNuevo = nuevoRolOpt.map(r -> r.nombre).orElse("Desconocido");

                // Registrar cambio en auditoría
                auditoriaService.registrarCambioRol(
                        authentication.getName(),
                        usuarioAModificar.getNombreUsuario(),
                        rolAnterior,
                        rolNuevo,
                        request
                );

                redirectAttributes.addFlashAttribute("mensaje",
                        "Rol actualizado exitosamente para " + usuarioAModificar.getNombreUsuario() +
                                ": " + rolAnterior + " → " + rolNuevo);
            } else {
                redirectAttributes.addFlashAttribute("error", "No se pudo actualizar el rol");
            }

        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error",
                    "Error al actualizar el rol: " + e.getMessage());

            // Registrar error en auditoría
            auditoriaService.registrarEvento(
                    authentication.getName(),
                    "CAMBIO_ROL_FALLIDO",
                    "/admin/actualizar-roles",
                    request,
                    com.example.demo.model.Auditoria.Resultado.FALLIDO,
                    "Error: " + e.getMessage()
            );
        }

        return "redirect:/dashboard";
    }
}
