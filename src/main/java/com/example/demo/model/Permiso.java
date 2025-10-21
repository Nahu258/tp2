package com.example.demo.model;

import jakarta.persistence.*;

/**
 * Clase Permiso - Representa un permiso en el sistema
 */
@Entity
@Table(name = "permisos")
public class Permiso {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    public String nombre;

    // Constructor vacío
    public Permiso() {
    }

    public Permiso(String nombre) {
        this.nombre = nombre;
    }

    // Getters y setters
    
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    @Override
    public String toString() {
        return nombre;
    }
}