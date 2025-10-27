package com.example.demo.repository;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Usuario;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuditoriaRepository extends JpaRepository<Auditoria, Long> {

    // Buscar por usuario
    Page<Auditoria> findByUsuarioOrderByFechaHoraDesc(Usuario usuario, Pageable pageable);

    // Buscar por acción
    Page<Auditoria> findByAccionOrderByFechaHoraDesc(String accion, Pageable pageable);

    // Buscar por resultado
    Page<Auditoria> findByResultadoOrderByFechaHoraDesc(Auditoria.Resultado resultado, Pageable pageable);

    // Buscar por rango de fechas
    Page<Auditoria> findByFechaHoraBetweenOrderByFechaHoraDesc(
            LocalDateTime inicio, LocalDateTime fin, Pageable pageable);

    // Buscar todos ordenados por fecha
    Page<Auditoria> findAllByOrderByFechaHoraDesc(Pageable pageable);

    // Contar eventos de un usuario
    long countByUsuario(Usuario usuario);

    // Contar eventos fallidos de un usuario
    long countByUsuarioAndResultado(Usuario usuario, Auditoria.Resultado resultado);

    // Obtener últimos eventos de un usuario
    List<Auditoria> findTop10ByUsuarioOrderByFechaHoraDesc(Usuario usuario);

    // Query personalizada: eventos de hoy
    @Query("SELECT a FROM Auditoria a WHERE DATE(a.fechaHora) = CURRENT_DATE ORDER BY a.fechaHora DESC")
    List<Auditoria> findEventosDeHoy();

    // Query personalizada: estadísticas por acción
    @Query("SELECT a.accion, COUNT(a) FROM Auditoria a GROUP BY a.accion ORDER BY COUNT(a) DESC")
    List<Object[]> getEstadisticasPorAccion();

    // Buscar intentos de acceso denegado por IP
    @Query("SELECT a FROM Auditoria a WHERE a.ipAddress = :ip AND a.resultado = 'BLOQUEADO' " +
           "AND a.fechaHora > :desde ORDER BY a.fechaHora DESC")
    List<Auditoria> findIntentosBloqueadosPorIP(
            @Param("ip") String ip, @Param("desde") LocalDateTime desde);
}