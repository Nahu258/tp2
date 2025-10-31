package com.example.demo.controller;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Usuario;
import com.example.demo.service.AuditoriaService;
import com.example.demo.service.SistemaLogin;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.io.PrintWriter;
import java.time.format.DateTimeFormatter;
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

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("dd/MM/yyyy");
    private static final DateTimeFormatter TIME_FORMATTER = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final DateTimeFormatter FILENAME_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

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
     * Exportar logs de auditoría a CSV
     */
    @GetMapping("/exportar")
    @PreAuthorize("hasRole('ADMIN')")
    public void exportarLogs(
            @RequestParam(defaultValue = "csv") String formato,
            @RequestParam(required = false) String filtroAccion,
            @RequestParam(required = false) String filtroUsuario,
            @RequestParam(required = false) String filtroResultado,
            Authentication authentication,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        auditoriaService.registrarEvento(
            authentication.getName(),
            "EXPORTAR_AUDITORIA",
            "/auditoria/exportar?formato=" + formato,
            request
        );

        // Obtener eventos con filtros aplicados
        Page<Auditoria> eventos;
        int maxRegistros = 10000; // Límite de registros para exportación
        
        if (filtroUsuario != null && !filtroUsuario.isEmpty()) {
            eventos = auditoriaService.buscarPorUsuario(filtroUsuario, 0, maxRegistros);
        } else if (filtroAccion != null && !filtroAccion.isEmpty()) {
            eventos = auditoriaService.buscarPorAccion(filtroAccion, 0, maxRegistros);
        } else if (filtroResultado != null && !filtroResultado.isEmpty()) {
            Auditoria.Resultado resultado = Auditoria.Resultado.valueOf(filtroResultado);
            eventos = auditoriaService.buscarPorResultado(resultado, 0, maxRegistros);
        } else {
            eventos = auditoriaService.obtenerTodosLosEventos(0, maxRegistros);
        }

        // Configurar respuesta HTTP para descarga
        String filename = "auditoria_" + java.time.LocalDateTime.now().format(FILENAME_FORMATTER) + ".csv";
        
        response.setContentType("text/csv; charset=UTF-8");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
        
        // Agregar BOM para UTF-8 (para que Excel lo detecte correctamente)
        response.getWriter().write('\ufeff');
        
        // Escribir CSV
        try (PrintWriter writer = response.getWriter()) {
            // Encabezados CSV
            writer.println("ID,Fecha,Hora,Usuario,Rol,Acción,Recurso,IP,Resultado,Detalles");
            
            // Datos
            for (Auditoria evento : eventos.getContent()) {
                writer.printf("%d,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                    evento.getId(),
                    evento.getFechaHora().format(DATE_FORMATTER),
                    evento.getFechaHora().format(TIME_FORMATTER),
                    escapeCsv(evento.getUsuario().getNombreUsuario()),
                    escapeCsv(evento.getUsuario().getRol().getNombre()),
                    escapeCsv(evento.getAccion()),
                    escapeCsv(evento.getRecurso()),
                    escapeCsv(evento.getIpAddress()),
                    evento.getResultado().name(),
                    escapeCsv(evento.getDetalles())
                );
            }
        }
    }

    /**
     * Escapa caracteres especiales para CSV
     */
    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        // Si contiene coma, comillas o salto de línea, envolver en comillas
        if (value.contains(",") || value.contains("\"") || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
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

        // TODO: Implementar vista de detalles
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