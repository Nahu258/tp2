package com.example.demo.service;

import com.example.demo.model.Usuario;
import com.example.demo.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Servicio personalizado para autenticación con Spring Security
 * Carga usuarios desde la base de datos y mapea roles/permisos dinámicamente
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Buscar usuario en la base de datos
        Usuario usuario = usuarioRepository.findByNombreUsuario(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));

        // Construir las autoridades (roles y permisos) dinámicamente desde la BD
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        // Agregar rol con prefijo ROLE_ (requerido por Spring Security)
        String roleName = usuario.getRol().nombre;
        String springRole = mapRoleToSpringRole(roleName);
        authorities.add(new SimpleGrantedAuthority(springRole));
        
        // DEBUG: Imprimir authorities para verificar
        System.out.println("🔑 Usuario: " + username + " | Rol: " + springRole);
        
        // Agregar permisos individuales con prefijo PERM_
        if (usuario.getRol().permisos != null && !usuario.getRol().permisos.isEmpty()) {
            usuario.getRol().permisos.forEach(permiso -> {
                String permisoNormalizado = "PERM_" + permiso.nombre
                    .toUpperCase()
                    .replace(" ", "_")
                    .replace("Ó", "O")
                    .replace("É", "E")
                    .replace("Í", "I")
                    .replace("Á", "A")
                    .replace("Ú", "U");
                authorities.add(new SimpleGrantedAuthority(permisoNormalizado));
                System.out.println("   ✓ Permiso: " + permisoNormalizado);
            });
        }

        // Retornar UserDetails con la contraseña ya hasheada desde BD
        return User.builder()
                .username(usuario.getNombreUsuario())
                .password(usuario.getClave()) // Ya está en formato BCrypt desde la BD
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }
    
    /**
     * Mapea los nombres de roles de la BD a roles de Spring Security
     * IMPORTANTE: "Administrador del Sistema" SIEMPRE se mapea a ROLE_ADMIN
     */
    private String mapRoleToSpringRole(String dbRoleName) {
        if (dbRoleName == null) {
            return "ROLE_USER";
        }
        
        // Normalizar para eliminar acentos y espacios extras
        String normalizado = dbRoleName.trim();
        
        switch (normalizado) {
            case "Administrador del Sistema":
                return "ROLE_ADMIN";
            case "Personal":
                return "ROLE_PERSONAL";
            case "Jefe de Área":
                return "ROLE_JEFE_AREA";
            case "Gerente":
                return "ROLE_GERENTE";
            case "Director":
                return "ROLE_DIRECTOR";
            case "Supervisor":
                return "ROLE_SUPERVISOR";
            default:
                // Para cualquier rol personalizado, crear uno genérico con ROLE_ prefix
                String rolGenerico = "ROLE_" + normalizado
                    .toUpperCase()
                    .replace(" ", "_")
                    .replace("Á", "A")
                    .replace("É", "E")
                    .replace("Í", "I")
                    .replace("Ó", "O")
                    .replace("Ú", "U");
                
                System.out.println("⚠️ Rol personalizado detectado: " + dbRoleName + " → " + rolGenerico);
                return rolGenerico;
        }
    }
}