package com.example.demo.service;

import com.example.demo.model.Auditoria;
import com.example.demo.model.Rol;
import com.example.demo.model.Usuario;
import com.example.demo.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Servicio personalizado para manejar usuarios OAuth2 (Google, GitHub, etc.)
 * Crea usuarios en la BD en el primer login y asigna authorities correctamente
 */
@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private SistemaLogin sistemaLogin;

    @Autowired
    private AuditoriaService auditoriaService; // ← MOVER AQUÍ AL INICIO

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        String provider = userRequest.getClientRegistration().getRegistrationId();
        String email = oauth2User.getAttribute("email");
        String login = oauth2User.getAttribute("login");
        String username = provider + "_" + (email != null ? email : login);
        
        Usuario usuario = obtenerOCrearUsuario(username, provider);
        
        // Registrar login OAuth2 en auditoría
        try {
            auditoriaService.registrarEvento(
                username, 
                "OAUTH2_LOGIN", 
                "/oauth2/" + provider,
                null, // request es null aquí
                Auditoria.Resultado.EXITOSO,
                "Autenticación OAuth2 con " + provider
            );
        } catch (Exception e) {
            System.err.println("⚠️ No se pudo registrar auditoría OAuth2: " + e.getMessage());
        }
        
        List<GrantedAuthority> authorities = construirAuthorities(usuario);
        
        String nameAttributeKey = userRequest.getClientRegistration()
            .getProviderDetails()
            .getUserInfoEndpoint()
            .getUserNameAttributeName();
            
        return new DefaultOAuth2User(
            authorities,
            oauth2User.getAttributes(),
            nameAttributeKey != null ? nameAttributeKey : "sub"
        );
    }
    
    /**
     * Obtiene un usuario existente o crea uno nuevo con rol Personal
     */
    private Usuario obtenerOCrearUsuario(String username, String provider) {
        Optional<Usuario> usuarioOpt = usuarioRepository.findByNombreUsuario(username);
        
        if (usuarioOpt.isPresent()) {
            return usuarioOpt.get();
        }
        
        // Crear nuevo usuario con rol Personal por defecto
        Optional<Rol> rolPersonal = sistemaLogin.obtenerRolPorNombre("Personal");
        
        if (rolPersonal.isEmpty()) {
            throw new OAuth2AuthenticationException("No se pudo asignar rol al usuario OAuth2");
        }
        
        Usuario nuevoUsuario = new Usuario();
        nuevoUsuario.setNombreUsuario(username);
        nuevoUsuario.setClave("OAUTH2_USER_" + provider); // No se usa para autenticación
        nuevoUsuario.setRol(rolPersonal.get());
        
        return usuarioRepository.save(nuevoUsuario);
    }
    
    /**
     * Construye las authorities (roles y permisos) desde el usuario de BD
     */
    private List<GrantedAuthority> construirAuthorities(Usuario usuario) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        
        // Agregar rol con prefijo ROLE_
        String roleName = usuario.getRol().nombre;
        String springRole = mapRoleToSpringRole(roleName);
        authorities.add(new SimpleGrantedAuthority(springRole));
        
        // Agregar permisos con prefijo PERM_
        if (usuario.getRol().permisos != null) {
            usuario.getRol().permisos.forEach(permiso -> {
                String permisoNormalizado = "PERM_" + permiso.nombre
                    .toUpperCase()
                    .replace(" ", "_")
                    .replace("Ó", "O")
                    .replace("É", "E");
                authorities.add(new SimpleGrantedAuthority(permisoNormalizado));
            });
        }
        
        return authorities;
    }
    
    /**
     * Mapea roles de BD a roles de Spring Security
     */
    private String mapRoleToSpringRole(String dbRoleName) {
        if (dbRoleName == null) {
            return "ROLE_USER";
        }
        
        switch (dbRoleName) {
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
                return "ROLE_" + dbRoleName
                    .toUpperCase()
                    .replace(" ", "_")
                    .replace("Á", "A")
                    .replace("É", "E")
                    .replace("Í", "I")
                    .replace("Ó", "O")
                    .replace("Ú", "U");
        }
    }
}