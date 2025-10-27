package com.example.demo.controller;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Usuario;
import com.example.demo.service.AuditoriaService;
import com.example.demo.service.SistemaLogin;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

/**
 * Controller para la gestión de Auditoría
 * Solo accesible por Administradores y Supervisores (según permisos CONTROL y GESTIÓN_TOTAL)
 */
@Controller
@RequestMapping("/auditoria")
public class AuditoriaController {

    @Autowired
    private AuditoriaService auditoriaService;

    @Autowired
    private SistemaLogin sistemaLogin;

    /**
     * Página principal de auditoría
     * Muestra todos los eventos con paginación
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    public String verAuditoria(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) String filtroAccion,
            @RequestParam(required = false) String filtroUsuario,
            @RequestParam(required = false) String filtroResultado,
            Authentication authentication,
            Model model,
            HttpServletRequest request) {

        // Registrar acceso a auditoría
        auditoriaService.registrarEvento(
            authentication.getName(),
            "ACCESO_AUDITORIA",
            "/auditoria",
            request
        );

        // Obtener usuario actual
        Optional<Usuario> usuarioOpt = sistemaLogin.obtenerUsuarioPorNombre(authentication.getName());
        if (usuarioOpt.isEmpty()) {
            return "redirect:/login";
        }
        Usuario usuario = usuarioOpt.get();

        // Aplicar filtros
        Page<Auditoria> eventos;
        
        if (filtroUsuario != null && !filtroUsuario.isEmpty()) {
            eventos = auditoriaService.buscarPorUsuario(filtroUsuario, page, size);
        } else if (filtroAccion != null && !filtroAccion.isEmpty()) {
            eventos = auditoriaService.buscarPorAccion(filtroAccion, page, size);
        } else if (filtroResultado != null && !filtroResultado.isEmpty()) {
            Auditoria.Resultado resultado = Auditoria.Resultado.valueOf(filtroResultado);
            eventos = auditoriaService.buscarPorResultado(resultado, page, size);
        } else {
            eventos = auditoriaService.obtenerTodosLosEventos(page, size);
        }

        // Obtener estadísticas
        List<Auditoria> eventosHoy = auditoriaService.obtenerEventosDeHoy();
        List<Object[]> estadisticas = auditoriaService.obtenerEstadisticasPorAccion();

        // Agregar datos al modelo
        model.addAttribute("usuario", usuario);
        model.addAttribute("nombreRol", usuario.getRol().nombre);
        model.addAttribute("eventos", eventos.getContent());
        model.addAttribute("paginaActual", page);
        model.addAttribute("totalPaginas", eventos.getTotalPages());
        model.addAttribute("totalEventos", eventos.getTotalElements());
        model.addAttribute("eventosHoy", eventosHoy.size());
        model.addAttribute("estadisticas", estadisticas);
        model.addAttribute("filtroAccion", filtroAccion);
        model.addAttribute("filtroUsuario", filtroUsuario);
        model.addAttribute("filtroResultado", filtroResultado);

        return "auditoria";
    }

    /**
     * Ver detalles de un evento específico
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    public String verDetalleEvento(
            @PathVariable Long id,
            Authentication authentication,
            Model model,
            HttpServletRequest request) {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "VER_DETALLE_AUDITORIA",
            "/auditoria/" + id,
            request
        );

        // Obtener usuario actual
        Optional<Usuario> usuarioOpt = sistemaLogin.obtenerUsuarioPorNombre(authentication.getName());
        if (usuarioOpt.isEmpty()) {
            return "redirect:/login";
        }

        // Aquí implementarías la lógica para mostrar detalles
        // Por ahora redirigimos a la lista
        return "redirect:/auditoria";
    }

    /**
     * Exportar logs de auditoría
     */
    @GetMapping("/exportar")
    @PreAuthorize("hasRole('ADMIN')")
    public String exportarLogs(
            @RequestParam(defaultValue = "csv") String formato,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "EXPORTAR_AUDITORIA",
            "/auditoria/exportar?formato=" + formato,
            request
        );

        // TODO: Implementar exportación a CSV/Excel
        redirectAttributes.addFlashAttribute("mensaje", 
            "Función de exportación en desarrollo. Formato: " + formato);

        return "redirect:/auditoria";
    }

    /**
     * API REST: Obtener eventos en formato JSON
     */
    @GetMapping("/api/eventos")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    @ResponseBody
    public Page<Auditoria> obtenerEventosJSON(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication authentication,
            HttpServletRequest request) {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "API_AUDITORIA",
            "/auditoria/api/eventos",
            request
        );

        return auditoriaService.obtenerTodosLosEventos(page, size);
    }

    /**
     * API REST: Obtener estadísticas
     */
    @GetMapping("/api/estadisticas")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPERVISOR')")
    @ResponseBody
    public List<Object[]> obtenerEstadisticasJSON(
            Authentication authentication,
            HttpServletRequest request) {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "API_ESTADISTICAS_AUDITORIA",
            "/auditoria/api/estadisticas",
            request
        );

        return auditoriaService.obtenerEstadisticasPorAccion();
    }

    /**
     * Limpiar logs antiguos (solo Admin)
     */
    @PostMapping("/limpiar")
    @PreAuthorize("hasRole('ADMIN')")
    public String limpiarLogsAntiguos(
            @RequestParam int diasAntiguedad,
            Authentication authentication,
            HttpServletRequest request,
            RedirectAttributes redirectAttributes) {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "LIMPIAR_LOGS",
            "/auditoria/limpiar",
            request,
            Auditoria.Resultado.EXITOSO,
            "Limpieza de logs mayores a " + diasAntiguedad + " días"
        );

        // TODO: Implementar limpieza de logs antiguos
        redirectAttributes.addFlashAttribute("mensaje", 
            "Función de limpieza en desarrollo. Días: " + diasAntiguedad);

        return "redirect:/auditoria";
    }
}