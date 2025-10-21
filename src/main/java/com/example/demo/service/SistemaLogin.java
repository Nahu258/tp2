package com.example.demo.service;

import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.repository.RolRepository;
import com.example.demo.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

/**
 * Clase SistemaLogin - Controla autenticación y autorización
 * Implementa los métodos según consigna del PDF:
 * - registrarUsuario(usuario)
 * - autenticar(nombre, clave)
 * - autorizar(usuario)
 */
@Service
public class SistemaLogin {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private RolRepository rolRepository;

    // Método según consigna: registrarUsuario(usuario)
    public boolean registrarUsuario(Usuario usuario) {
        if (usuarioRepository.existsByNombreUsuario(usuario.getNombreUsuario())) {
            return false;
        }
        usuarioRepository.save(usuario);
        return true;
    }

    // Método según consigna: autenticar(nombre, clave)
    public Usuario autenticar(String nombre, String clave) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByNombreUsuario(nombre);
        
        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            if (usuario.validarClave(clave)) {
                return usuario;
            }
        }
        return null;
    }

    // Método según consigna: autorizar(usuario)
    // Polimorfismo: diferentes respuestas según el rol
    public String autorizar(Usuario usuario) {
        if (usuario == null) {
            return "Acceso denegado.";
        }

        StringBuilder resultado = new StringBuilder();
        resultado.append("✓ Usuario autenticado: ").append(usuario.getNombreUsuario()).append("\n");
        resultado.append("✓ Rol: ").append(usuario.getRol().nombre).append("\n");
        resultado.append("✓ Permisos: ").append(usuario.getRol().getNombresPermisos()).append("\n\n");

        // Polimorfismo: comportamiento diferente según rol
        String nombreRol = usuario.getRol().nombre;
        
        if (nombreRol.equals("Administrador del Sistema")) {
            resultado.append("→ Acceso completo al sistema (GESTIÓN TOTAL)");
        } else if (nombreRol.equals("Director")) {
            resultado.append("→ Acceso a lectura, edición, aprobación y toma de decisiones");
        } else if (nombreRol.equals("Gerente")) {
            resultado.append("→ Acceso a informes y aprobaciones");
        } else if (nombreRol.equals("Jefe de Área")) {
            resultado.append("→ Acceso a lectura y edición");
        } else if (nombreRol.equals("Supervisor")) {
            resultado.append("→ Acceso a lectura y control");
        } else if (nombreRol.equals("Personal")) {
            resultado.append("→ Acceso básico (solo lectura)");
        }

        return resultado.toString();
    }

    // Método auxiliar para obtener rol por nombre
    public Optional<Rol> obtenerRolPorNombre(String nombre) {
        return rolRepository.findByNombre(nombre);
    }

    // Método auxiliar para verificar permisos específicos
    public boolean tienePermiso(Usuario usuario, String permiso) {
        return usuario != null && usuario.getRol().tienePermiso(permiso);
    }

    /**
     * Obtener usuario por nombre de usuario
     * Utilizado por Spring Security para cargar usuarios autenticados
     * @param nombreUsuario Nombre del usuario a buscar
     * @return Optional con el usuario si existe
     */
    public Optional<Usuario> obtenerUsuarioPorNombre(String nombreUsuario) {
        return usuarioRepository.findByNombreUsuario(nombreUsuario);
    }

    /**
     * Obtener todos los usuarios del sistema
     * Utilizado para la gestión de usuarios por parte del administrador
     * @return Lista de todos los usuarios registrados
     */
    public List<Usuario> obtenerTodosLosUsuarios() {
        return usuarioRepository.findAll();
    }

    /**
     * Obtener todos los roles disponibles en el sistema
     * Utilizado para mostrar opciones de roles en la gestión de usuarios
     * @return Lista de todos los roles
     */
    public List<Rol> obtenerTodosLosRoles() {
        return rolRepository.findAll();
    }

    /**
     * Actualizar el rol de un usuario existente
     * Solo debe ser utilizado por administradores del sistema
     * @param usuarioId ID del usuario a actualizar
     * @param nuevoRolId ID del nuevo rol a asignar
     * @return true si se actualizó correctamente, false en caso contrario
     */
    public boolean actualizarRolUsuario(Long usuarioId, Long nuevoRolId) {
        try {
            Optional<Usuario> usuarioOpt = usuarioRepository.findById(usuarioId);
            Optional<Rol> rolOpt = rolRepository.findById(nuevoRolId);
            
            if (usuarioOpt.isPresent() && rolOpt.isPresent()) {
                Usuario usuario = usuarioOpt.get();
                Rol nuevoRol = rolOpt.get();
                
                usuario.setRol(nuevoRol);
                usuarioRepository.save(usuario);
                
                return true;
            }
            
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}