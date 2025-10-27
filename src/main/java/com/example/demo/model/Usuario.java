package com.example.demo.model;

import jakarta.persistence.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Clase Usuario - Encapsulación de datos del usuario
 * Atributos privados protegen la información sensible
 */
@Entity
@Table(name = "usuarios")
public class Usuario {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(name = "nombre_usuario", nullable = false, unique = true)
    private String nombreUsuario;
    
    @Column(nullable = false)
    private String clave;
    
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "rol_id", nullable = false)
    private Rol rol;

    // Constructor vacío requerido por JPA
    public Usuario() {
    }

    // Constructor - AHORA recibe la contraseña YA HASHEADA
    // La responsabilidad de hashear está en el controlador
    public Usuario(String nombreUsuario, String claveHasheada, Rol rol) {
        this.nombreUsuario = nombreUsuario;
        this.clave = claveHasheada; // Ya viene hasheada desde el controlador
        this.rol = rol;
    }

    // Métodos públicos según consigna
    
    public String getNombreUsuario() {
        return nombreUsuario;
    }

    public Rol getRol() {
        return rol;
    }

    // ELIMINADO: El método validarClave ya no es necesario
    // Spring Security maneja la validación automáticamente
    
    // Getters y setters adicionales para JPA
    
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setNombreUsuario(String nombreUsuario) {
        this.nombreUsuario = nombreUsuario;
    }

    public String getClave() {
        return clave;
    }

    public void setClave(String clave) {
        this.clave = clave;
    }

    public void setRol(Rol rol) {
        this.rol = rol;
    }
    
    @Override
    public String toString() {
        return "Usuario{" +
                "id=" + id +
                ", nombreUsuario='" + nombreUsuario + '\'' +
                ", rol=" + (rol != null ? rol.nombre : "null") +
                '}';
    }
}