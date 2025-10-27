package com.example.demo.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "auditoria")
public class Auditoria {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "usuario_id", nullable = false)
    private Usuario usuario;

    @Column(nullable = false, length = 100)
    private String accion;

    @Column(length = 255)
    private String recurso;

    @Column(name = "fecha_hora", nullable = false, updatable = false)
    private LocalDateTime fechaHora;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(columnDefinition = "TEXT")
    private String detalles;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Resultado resultado;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    public enum Resultado {
        EXITOSO, FALLIDO, BLOQUEADO
    }

    // Constructor vacío
    public Auditoria() {
        this.fechaHora = LocalDateTime.now();
        this.resultado = Resultado.EXITOSO;
    }

    // Constructor completo
    public Auditoria(Usuario usuario, String accion, String recurso, 
                     String ipAddress, String detalles, Resultado resultado) {
        this.usuario = usuario;
        this.accion = accion;
        this.recurso = recurso;
        this.ipAddress = ipAddress;
        this.detalles = detalles;
        this.resultado = resultado;
        this.fechaHora = LocalDateTime.now();
    }

    // Getters y Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Usuario getUsuario() { return usuario; }
    public void setUsuario(Usuario usuario) { this.usuario = usuario; }

    public String getAccion() { return accion; }
    public void setAccion(String accion) { this.accion = accion; }

    public String getRecurso() { return recurso; }
    public void setRecurso(String recurso) { this.recurso = recurso; }

    public LocalDateTime getFechaHora() { return fechaHora; }
    public void setFechaHora(LocalDateTime fechaHora) { this.fechaHora = fechaHora; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getDetalles() { return detalles; }
    public void setDetalles(String detalles) { this.detalles = detalles; }

    public Resultado getResultado() { return resultado; }
    public void setResultado(Resultado resultado) { this.resultado = resultado; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    @PrePersist
    protected void onCreate() {
        if (fechaHora == null) {
            fechaHora = LocalDateTime.now();
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] %s - %s realizó %s en %s - Resultado: %s",
                fechaHora, ipAddress, usuario.getNombreUsuario(), accion, recurso, resultado);
    }
}