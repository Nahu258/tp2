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
        try {
            OAuth2User oauth2User = super.loadUser(userRequest);
            
            String provider = userRequest.getClientRegistration().getRegistrationId();
            
            // ✅ CORREGIR: Obtener atributos según el proveedor
            String email = oauth2User.getAttribute("email");
            String login = oauth2User.getAttribute("login"); // GitHub
            String name = oauth2User.getAttribute("name");
            String sub = oauth2User.getAttribute("sub"); // Google ID
            
            // ✅ DEBUG: Ver qué datos llegan
            System.out.println("🔍 OAUTH2 DEBUG:");
            System.out.println("   Provider: " + provider);
            System.out.println("   Email: " + email);
            System.out.println("   Login: " + login);
            System.out.println("   Name: " + name);
            System.out.println("   Sub (ID): " + sub);
            
            // ✅ IMPORTANTE: Construir username de forma consistente
            String username;
            String displayName;
            
            if ("google".equals(provider)) {
                // Para Google, SIEMPRE usar el email
                if (email == null || email.isEmpty()) {
                    throw new OAuth2AuthenticationException("Google no proporcionó el email");
                }
                username = email;
                displayName = name != null ? name : email;
                
            } else if ("github".equals(provider)) {
                // Para GitHub, usar el login
                if (login == null || login.isEmpty()) {
                    throw new OAuth2AuthenticationException("GitHub no proporcionó el login");
                }
                username = "github_" + login;
                displayName = name != null ? name : login;
                
            } else {
                // Para otros proveedores
                username = provider + "_" + (email != null ? email : sub);
                displayName = name != null ? name : username;
            }
            
            System.out.println("   ✅ Username generado: " + username);
            
            // Obtener o crear usuario
            Usuario usuario = obtenerOCrearUsuario(username, provider, displayName);
            System.out.println("   ✅ Usuario obtenido/creado: " + usuario.getNombreUsuario());
            System.out.println("   ✅ Usuario ID en BD: " + usuario.getId());
            
            // Registrar login OAuth2 en auditoría
            try {
                auditoriaService.registrarEvento(
                    username, // ✅ Usar el username completo, no el sub
                    "OAUTH2_LOGIN", 
                    "/oauth2/" + provider,
                    null,
                    Auditoria.Resultado.EXITOSO,
                    "Autenticación OAuth2 con " + provider + " - " + displayName
                );
                System.out.println("   ✅ Auditoría registrada correctamente");
            } catch (Exception e) {
                System.err.println("   ⚠️ No se pudo registrar auditoría OAuth2: " + e.getMessage());
                e.printStackTrace();
            }
            
            // Construir authorities
            List<GrantedAuthority> authorities = construirAuthorities(usuario);
            System.out.println("   ✅ Authorities: " + authorities);
            
            // Obtener el atributo clave para el nombre
            String nameAttributeKey = userRequest.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
            
            // String finalNameKey = nameAttributeKey != null && !nameAttributeKey.isEmpty() ? nameAttributeKey : "sub";
            String finalNameKey = "google".equals(provider) ? "email" : nameAttributeKey;
            System.out.println("   ✅ Name attribute key: " + finalNameKey);
                
            return new DefaultOAuth2User(
                authorities,
                oauth2User.getAttributes(), 
                finalNameKey
            );
            
        } catch (Exception e) {
            System.err.println("❌ ERROR EN OAUTH2 SERVICE: " + e.getMessage());
            e.printStackTrace();
            throw new OAuth2AuthenticationException("Error al procesar usuario OAuth2: " + e.getMessage());
        }
    }
    
    /**
     * Obtiene un usuario existente o crea uno nuevo con rol Personal
     */
    private Usuario obtenerOCrearUsuario(String username, String provider, String displayName) {
        try {
            Optional<Usuario> usuarioOpt = usuarioRepository.findByNombreUsuario(username);

            if (usuarioOpt.isPresent()) {
                System.out.println("   ✅ Usuario existente encontrado: " + username);
                return usuarioOpt.get();
            }

            System.out.println("   ➕ Creando nuevo usuario OAuth2: " + username);

            // Crear nuevo usuario con rol Personal por defecto
            Optional<Rol> rolPersonal = sistemaLogin.obtenerRolPorNombre("Personal");

            if (rolPersonal.isEmpty()) {
                System.err.println("   ❌ Rol 'Personal' no encontrado en la BD");
                throw new OAuth2AuthenticationException("No se pudo asignar rol al usuario OAuth2");
            }

            Usuario nuevoUsuario = new Usuario();
            nuevoUsuario.setNombreUsuario(username);
            nuevoUsuario.setClave("OAUTH2_USER_" + provider); // No se usa para autenticación
            nuevoUsuario.setRol(rolPersonal.get());

            Usuario usuarioGuardado = usuarioRepository.save(nuevoUsuario);
            System.out.println("   ✅ Usuario OAuth2 creado exitosamente: " + usuarioGuardado.getId());

            return usuarioGuardado;

        } catch (Exception e) {
            System.err.println("   ❌ Error al obtener/crear usuario: " + e.getMessage());
            e.printStackTrace();
            throw new OAuth2AuthenticationException("Error al crear usuario: " + e.getMessage());
        }
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