package com.example.demo.model;

import jakarta.persistence.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Clase Rol - Define permisos por rol
 * Atributos públicos según consigna: nombre y permisos
 */
@Entity
@Table(name = "roles")
public class Rol {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    public String nombre;
    
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "rol_permisos",
        joinColumns = @JoinColumn(name = "rol_id"),
        inverseJoinColumns = @JoinColumn(name = "permiso_id")
    )
    public List<Permiso> permisos = new ArrayList<>();

    // Constructor vacío requerido por JPA
    public Rol() {
    }

    // Constructor según consigna: constructor(nombre, permisos)
    public Rol(String nombre, List<Permiso> permisos) {
        this.nombre = nombre;
        this.permisos = permisos != null ? permisos : new ArrayList<>();
    }

    // Método según consigna: tienePermiso(accion)
    public boolean tienePermiso(String accion) {
        if (permisos == null) return false;
        return permisos.stream()
            .anyMatch(p -> p.nombre.equals(accion));
    }

    // Método auxiliar para obtener nombres de permisos
    public List<String> getNombresPermisos() {
        return permisos.stream()
            .map(p -> p.nombre)
            .collect(Collectors.toList());
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

    public List<Permiso> getPermisos() {
        return permisos;
    }

    public void setPermisos(List<Permiso> permisos) {
        this.permisos = permisos;
    }

    @Override
    public String toString() {
        return nombre + " " + getNombresPermisos();
    }
}