package com.example.demo.service;

import com.example.demo.dto.RolDTO;
import com.example.demo.model.Permiso;
import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.repository.PermisoRepository;
import com.example.demo.repository.RolRepository;
import com.example.demo.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


/**
 * Servicio para gestión dinámica de Roles y Permisos
 * Permite CRUD completo y asignación de permisos a roles
 */
@Service
@Transactional(readOnly = true) // ← Agregar a nivel de clase
public class RolPermisoService {

    @Autowired
    private RolRepository rolRepository;

    @Autowired
    private PermisoRepository permisoRepository;

    @Autowired
    private UsuarioRepository usuarioRepository;

    // ==================== ROLES ====================

    /**
     * Obtener todos los roles con permisos cargados
     */
    public List<Rol> obtenerTodosLosRoles() {
        List<Rol> roles = rolRepository.findAll();
        // Forzar carga de permisos
        roles.forEach(rol -> {
            if (rol.permisos != null) {
                rol.permisos.size(); // Inicializa la colección lazy
            }
        });
        return roles;
    }

    /**
     * Obtener un rol por ID
     */
    public Optional<Rol> obtenerRolPorId(Long id) {
        Optional<Rol> rolOpt = rolRepository.findById(id);
        rolOpt.ifPresent(rol -> {
            if (rol.permisos != null) {
                rol.permisos.size();
            }
        });
        return rolOpt;
    }

    /**
     * Crear un nuevo rol
     */
    @Transactional
    public Rol crearRol(String nombre) {
        // Validar que no exista
        if (rolRepository.findByNombre(nombre).isPresent()) {
            throw new IllegalArgumentException("Ya existe un rol con ese nombre");
        }

        Rol nuevoRol = new Rol();
        nuevoRol.nombre = nombre;
        nuevoRol.permisos = new ArrayList<>();
        return rolRepository.save(nuevoRol);
    }

    /**
     * Actualizar nombre de un rol
     */
    @Transactional
    public Rol actualizarRol(Long id, String nuevoNombre) {
        Rol rol = rolRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Rol no encontrado"));

        // Validar que el nuevo nombre no esté en uso por otro rol
        Optional<Rol> rolExistente = rolRepository.findByNombre(nuevoNombre);
        if (rolExistente.isPresent() && !rolExistente.get().getId().equals(id)) {
            throw new IllegalArgumentException("Ya existe un rol con ese nombre");
        }

        rol.nombre = nuevoNombre;
        return rolRepository.save(rol);
    }

    /**
     * Eliminar un rol
     */
    @Transactional
    public boolean eliminarRol(Long id) {
        Optional<Rol> rolOpt = rolRepository.findById(id);
        if (rolOpt.isEmpty()) {
            return false;
        }

        Rol rol = rolOpt.get();

        // No permitir eliminar roles del sistema
        List<String> rolesProtegidos = List.of(
            "Personal", "Jefe de Área", "Gerente",  // ← Corregir
            "Director", "Supervisor", "Administrador del Sistema"
        );

        if (rolesProtegidos.contains(rol.nombre)) {
            throw new IllegalArgumentException("No se puede eliminar un rol del sistema");
        }

        // Verificar que no haya usuarios con este rol
        List<Usuario> usuariosConRol = usuarioRepository.findByRol(rol);
        if (!usuariosConRol.isEmpty()) {
            throw new IllegalArgumentException(
                "No se puede eliminar el rol porque hay " + usuariosConRol.size() + " usuario(s) asignado(s)"
            );
        }

        rolRepository.delete(rol);
        return true;
    }

    // ==================== PERMISOS ====================

    /**
     * Obtener todos los permisos
     */
    public List<Permiso> obtenerTodosLosPermisos() {
        return permisoRepository.findAll();
    }

    /**
     * Obtener un permiso por ID
     */
    public Optional<Permiso> obtenerPermisoPorId(Long id) {
        return permisoRepository.findById(id);
    }

    /**
     * Crear un nuevo permiso
     */
    @Transactional
    public Permiso crearPermiso(String nombre) {
        String nombreNormalizado = nombre.toUpperCase().replace(" ", "_");
        
        if (permisoRepository.findByNombre(nombreNormalizado).isPresent()) {
            throw new IllegalArgumentException("Ya existe un permiso con ese nombre");
        }

        Permiso nuevoPermiso = new Permiso();
        nuevoPermiso.nombre = nombreNormalizado;
        return permisoRepository.save(nuevoPermiso);
    }

    /**
     * Actualizar nombre de un permiso
     */
    @Transactional
    public Permiso actualizarPermiso(Long id, String nuevoNombre) {
        Permiso permiso = permisoRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Permiso no encontrado"));

        String nombreNormalizado = nuevoNombre.toUpperCase().replace(" ", "_");

        Optional<Permiso> permisoExistente = permisoRepository.findByNombre(nombreNormalizado);
        if (permisoExistente.isPresent() && !permisoExistente.get().getId().equals(id)) {
            throw new IllegalArgumentException("Ya existe un permiso con ese nombre");
        }

        permiso.nombre = nombreNormalizado;
        return permisoRepository.save(permiso);
    }

    /**
     * Eliminar un permiso
     */
    @Transactional
    public boolean eliminarPermiso(Long id) {
        Optional<Permiso> permisoOpt = permisoRepository.findById(id);
        if (permisoOpt.isEmpty()) {
            return false;
        }

        Permiso permiso = permisoOpt.get();

        List<String> permisosProtegidos = List.of(
            "LECTURA", "EDICIÓN", "APROBACIÓN",  // ← Corregir
            "DECISIÓN", "CONTROL", "GESTIÓN_TOTAL"
        );

        if (permisosProtegidos.contains(permiso.nombre)) {
            throw new IllegalArgumentException("No se puede eliminar un permiso del sistema");
        }

        // Eliminar el permiso de todos los roles
        List<Rol> roles = rolRepository.findAll();
        for (Rol rol : roles) {
            if (rol.permisos != null) {
                rol.permisos.size(); // Inicializar
                rol.permisos.removeIf(p -> p.getId().equals(id));
                rolRepository.save(rol);
            }
        }

        permisoRepository.delete(permiso);
        return true;
    }

    // ==================== ASIGNACIÓN ROLES-PERMISOS ====================

    /**
     * Asignar permisos a un rol
     */
    @Transactional
    public Rol asignarPermisosARol(Long rolId, Set<Long> permisosIds) {
        Rol rol = rolRepository.findById(rolId)
            .orElseThrow(() -> new IllegalArgumentException("Rol no encontrado"));

        // Inicializar y limpiar permisos actuales
        if (rol.permisos == null) {
            rol.permisos = new ArrayList<>();
        } else {
            rol.permisos.size(); // Inicializar lazy collection
            rol.permisos.clear();
        }

        // Agregar nuevos permisos
        if (permisosIds != null && !permisosIds.isEmpty()) {
            for (Long permisoId : permisosIds) {
                Permiso permiso = permisoRepository.findById(permisoId)
                    .orElseThrow(() -> new IllegalArgumentException("Permiso no encontrado: " + permisoId));
                rol.permisos.add(permiso);
            }
        }

        return rolRepository.save(rol);
    }

    /**
     * Obtener permisos de un rol
     */
    public List<Permiso> obtenerPermisosDeRol(Long rolId) {
        Rol rol = rolRepository.findById(rolId)
            .orElseThrow(() -> new IllegalArgumentException("Rol no encontrado"));
        
        if (rol.permisos != null) {
            rol.permisos.size(); // Inicializar
        }
        
        return rol.permisos;
    }

    /**
     * Verificar si un rol tiene un permiso específico
     */
    public boolean rolTienePermiso(Long rolId, Long permisoId) {
        Rol rol = rolRepository.findById(rolId)
            .orElseThrow(() -> new IllegalArgumentException("Rol no encontrado"));
        
        if (rol.permisos != null) {
            rol.permisos.size();
            return rol.permisos.stream()
                .anyMatch(p -> p.getId().equals(permisoId));
        }
        
        return false;
    }

    /**
     * Contar usuarios asignados a un rol
     */
    public long contarUsuariosPorRol(Long rolId) {
        Rol rol = rolRepository.findById(rolId)
            .orElseThrow(() -> new IllegalArgumentException("Rol no encontrado"));
        
        return usuarioRepository.findByRol(rol).size();
    }

    /**
     * Obtener todos los roles como DTOs (sin problemas de Hibernate)
     */
    @Transactional(readOnly = true)
    public List<RolDTO> obtenerTodosLosRolesDTO() {
        List<Rol> roles = rolRepository.findAll();

        return roles.stream()
            .map(rol -> {
                // Forzar carga de permisos
                if (rol.permisos != null) {
                    try {
                        rol.permisos.size(); // Inicializa la colección lazy
                    } catch (Exception e) {
                        System.err.println("⚠️ Error al cargar permisos del rol: " + rol.nombre);
                    }
                }
                return new RolDTO(rol);
            })
            .collect(Collectors.toList());
    }
}