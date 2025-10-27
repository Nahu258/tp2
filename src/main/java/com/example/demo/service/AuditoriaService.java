package com.example.demo.service;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Usuario;
import com.example.demo.repository.AuditoriaRepository;
import com.example.demo.repository.UsuarioRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Servicio de Auditoría - Registra todas las acciones del sistema
 * Cumple con los requerimientos de la consigna:
 * - Registro de acciones en log persistente (fecha, usuario, acción)
 * - Visualización de eventos por administradores
 */
@Service
public class AuditoriaService {

    @Autowired
    private AuditoriaRepository auditoriaRepository;

    @Autowired
    private UsuarioRepository usuarioRepository;

    /**
     * Registrar evento de auditoría de forma asíncrona
     * @param nombreUsuario Usuario que realiza la acción
     * @param accion Tipo de acción realizada
     * @param recurso Recurso afectado
     * @param request Request HTTP para obtener IP y User-Agent
     * @param resultado Resultado de la acción
     * @param detalles Información adicional
     */
    @Async
    @Transactional
    public void registrarEvento(String nombreUsuario, String accion, String recurso,
                                HttpServletRequest request, Auditoria.Resultado resultado,
                                String detalles) {
        try {
            Optional<Usuario> usuarioOpt = usuarioRepository.findByNombreUsuario(nombreUsuario);
            
            if (usuarioOpt.isEmpty()) {
                System.err.println("⚠️ No se pudo registrar auditoría: Usuario no encontrado - " + nombreUsuario);
                return;
            }

            Auditoria evento = new Auditoria();
            evento.setUsuario(usuarioOpt.get());
            evento.setAccion(accion);
            evento.setRecurso(recurso);
            evento.setResultado(resultado);
            evento.setDetalles(detalles);

            if (request != null) {
                evento.setIpAddress(obtenerIPReal(request));
                evento.setUserAgent(request.getHeader("User-Agent"));
            }

            auditoriaRepository.save(evento);
            
            System.out.println("✓ Auditoría registrada: " + evento);
            
        } catch (Exception e) {
            System.err.println("❌ Error al registrar auditoría: " + e.getMessage());
        }
    }

    /**
     * Sobrecarga: Registrar evento exitoso sin detalles
     */
    @Async
    public void registrarEvento(String nombreUsuario, String accion, String recurso,
                                HttpServletRequest request) {
        registrarEvento(nombreUsuario, accion, recurso, request, Auditoria.Resultado.EXITOSO, null);
    }

    /**
     * Registrar login exitoso
     */
    public void registrarLoginExitoso(String nombreUsuario, HttpServletRequest request) {
        registrarEvento(nombreUsuario, "LOGIN_EXITOSO", "/login", 
                       request, Auditoria.Resultado.EXITOSO, "Autenticación correcta");
    }

    /**
     * Registrar login OAuth2
     */
    public void registrarLoginOAuth2(String nombreUsuario, String provider, HttpServletRequest request) {
        registrarEvento(nombreUsuario, "OAUTH2_LOGIN", "/oauth2/" + provider,
                       request, Auditoria.Resultado.EXITOSO, "Autenticación OAuth2: " + provider);
    }

    /**
     * Registrar login fallido
     */
    public void registrarLoginFallido(String nombreUsuario, HttpServletRequest request, String motivo) {
        registrarEvento(nombreUsuario, "LOGIN_FALLIDO", "/login",
                       request, Auditoria.Resultado.FALLIDO, "Motivo: " + motivo);
    }

    /**
     * Registrar logout
     */
    public void registrarLogout(String nombreUsuario, HttpServletRequest request) {
        registrarEvento(nombreUsuario, "LOGOUT", "/logout",
                       request, Auditoria.Resultado.EXITOSO, "Sesión cerrada correctamente");
    }

    /**
     * Registrar acceso denegado
     */
    public void registrarAccesoDenegado(String nombreUsuario, String recurso, HttpServletRequest request) {
        registrarEvento(nombreUsuario, "ACCESO_DENEGADO", recurso,
                       request, Auditoria.Resultado.BLOQUEADO, "Permisos insuficientes");
    }

    /**
     * Registrar cambio de rol
     */
    public void registrarCambioRol(String adminUser, String usuarioModificado, 
                                   String rolAnterior, String rolNuevo, HttpServletRequest request) {
        String detalles = String.format("Usuario '%s' cambió de '%s' a '%s'", 
                                       usuarioModificado, rolAnterior, rolNuevo);
        registrarEvento(adminUser, "CAMBIO_ROL", "/admin/actualizar-roles",
                       request, Auditoria.Resultado.EXITOSO, detalles);
    }

    /**
     * Obtener todos los eventos con paginación
     */
    public Page<Auditoria> obtenerTodosLosEventos(int pagina, int tamanio) {
        Pageable pageable = PageRequest.of(pagina, tamanio);
        return auditoriaRepository.findAllByOrderByFechaHoraDesc(pageable);
    }

    /**
     * Buscar eventos por usuario
     */
    public Page<Auditoria> buscarPorUsuario(String nombreUsuario, int pagina, int tamanio) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByNombreUsuario(nombreUsuario);
        if (usuarioOpt.isEmpty()) {
            return Page.empty();
        }
        Pageable pageable = PageRequest.of(pagina, tamanio);
        return auditoriaRepository.findByUsuarioOrderByFechaHoraDesc(usuarioOpt.get(), pageable);
    }

    /**
     * Buscar eventos por acción
     */
    public Page<Auditoria> buscarPorAccion(String accion, int pagina, int tamanio) {
        Pageable pageable = PageRequest.of(pagina, tamanio);
        return auditoriaRepository.findByAccionOrderByFechaHoraDesc(accion, pageable);
    }

    /**
     * Buscar eventos por resultado
     */
    public Page<Auditoria> buscarPorResultado(Auditoria.Resultado resultado, int pagina, int tamanio) {
        Pageable pageable = PageRequest.of(pagina, tamanio);
        return auditoriaRepository.findByResultadoOrderByFechaHoraDesc(resultado, pageable);
    }

    /**
     * Obtener eventos de hoy
     */
    public List<Auditoria> obtenerEventosDeHoy() {
        return auditoriaRepository.findEventosDeHoy();
    }

    /**
     * Obtener estadísticas por acción
     */
    public List<Object[]> obtenerEstadisticasPorAccion() {
        return auditoriaRepository.getEstadisticasPorAccion();
    }

    /**
     * Detectar intentos de acceso sospechosos
     * @param ip Dirección IP a verificar
     * @param minutos Ventana de tiempo en minutos
     * @return Lista de intentos bloqueados
     */
    public List<Auditoria> detectarIntentosSospechosos(String ip, int minutos) {
        LocalDateTime desde = LocalDateTime.now().minusMinutes(minutos);
        return auditoriaRepository.findIntentosBloqueadosPorIP(ip, desde);
    }

    /**
     * Obtener IP real del cliente (considerando proxies)
     */
    private String obtenerIPReal(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // Si hay múltiples IPs, tomar la primera
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}