package com.example.demo.dto;

import com.example.demo.model.Permiso;
import com.example.demo.model.Rol;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * DTO para transferir datos de Rol sin problemas de Hibernate
 */
public class RolDTO {
    private Long id;
    private String nombre;
    private List<String> permisos;
    private boolean esProtegido;
    private int cantidadPermisos;

    public RolDTO(Rol rol) {
        this.id = rol.getId();
        this.nombre = rol.getNombre();
        
        // Cargar permisos de forma segura
        if (rol.permisos != null) {
            try {
                this.permisos = rol.permisos.stream()
                    .map(Permiso::getNombre)
                    .collect(Collectors.toList());
                this.cantidadPermisos = rol.permisos.size();
            } catch (Exception e) {
                this.permisos = new ArrayList<>();
                this.cantidadPermisos = 0;
            }
        } else {
            this.permisos = new ArrayList<>();
            this.cantidadPermisos = 0;
        }
        
        // Verificar si es rol protegido
        List<String> rolesProtegidos = List.of(
            "Personal", "Jefe de Área", "Gerente", 
            "Director", "Supervisor", "Administrador del Sistema"
        );
        this.esProtegido = rolesProtegidos.contains(rol.getNombre());
    }

    // Getters
    public Long getId() { return id; }
    public String getNombre() { return nombre; }
    public List<String> getPermisos() { return permisos; }
    public boolean isEsProtegido() { return esProtegido; }
    public int getCantidadPermisos() { return cantidadPermisos; }
}