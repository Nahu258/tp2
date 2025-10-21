package com.example.demo.model;

import jakarta.persistence.*;
import org.mindrot.jbcrypt.BCrypt;

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

    // Constructor para NUEVO usuario (hashea la contraseña)
    // Usado en registro manual
    public Usuario(String nombreUsuario, String clave, Rol rol) {
        this.nombreUsuario = nombreUsuario;
        // Solo hashear si la clave no está ya hasheada
        if (clave != null && !clave.startsWith("$2a$")) {
            this.clave = BCrypt.hashpw(clave, BCrypt.gensalt());
        } else {
            this.clave = clave;
        }
        this.rol = rol;
    }

    // Métodos públicos según consigna
    
    public String getNombreUsuario() {
        return nombreUsuario;
    }

    public Rol getRol() {
        return rol;
    }

    public boolean validarClave(String entradaClave) {
        // Validar solo si la clave está hasheada
        if (clave != null && clave.startsWith("$2a$")) {
            return BCrypt.checkpw(entradaClave, clave);
        }
        // Para usuarios OAuth2 que no tienen contraseña real
        return false;
    }

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