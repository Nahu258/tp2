package com.example.demo.config;

import com.example.demo.service.AuditoriaService;
import com.example.demo.service.CustomOAuth2UserService;
import com.example.demo.service.CustomUserDetailsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import java.io.IOException;

/**
 * Configuración de Spring Security con OAuth2 y Sistema de Auditoría
 * Integra autenticación tradicional (usuario/contraseña) con OAuth2
 * Registra todos los eventos de autenticación en el sistema de auditoría
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private AuditoriaService auditoriaService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Handler para login exitoso - Registra en auditoría
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, 
                                               HttpServletResponse response, 
                                               Authentication authentication) 
                                               throws IOException, ServletException {
                                            
                // DEBUG: Verificar authorities
                System.out.println("🔐 LOGIN EXITOSO");
                System.out.println("   Usuario: " + authentication.getName());
                System.out.println("   Authorities: " + authentication.getAuthorities());
                                            
                // Registrar login exitoso en auditoría
                String username = authentication.getName();
                try {
                    auditoriaService.registrarLoginExitoso(username, request);
                    System.out.println("✓ LOGIN EXITOSO: " + username + " desde " + request.getRemoteAddr());
                } catch (Exception e) {
                    System.err.println("⚠️ Error al registrar auditoría de login: " + e.getMessage());
                }
                
                // Redirigir al dashboard
                response.sendRedirect("/dashboard");
            }
        };
    }

    /**
     * Handler para login fallido - Registra en auditoría
     */
    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler("/login?error=true") {
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, 
                                               HttpServletResponse response, 
                                               AuthenticationException exception) 
                                               throws IOException, ServletException {
                
                // Obtener username del intento fallido
                String username = request.getParameter("nombre");
                
                if (username != null && !username.isEmpty()) {
                    try {
                        String motivo = exception.getMessage() != null ? exception.getMessage() : "Credenciales incorrectas";
                        auditoriaService.registrarLoginFallido(username, request, motivo);
                        System.out.println("✗ LOGIN FALLIDO: " + username + " - Motivo: " + motivo);
                    } catch (Exception e) {
                        System.err.println("⚠️ Error al registrar auditoría de login fallido: " + e.getMessage());
                    }
                }
                
                // Continuar con el flujo normal
                super.onAuthenticationFailure(request, response, exception);
            }
        };
    }

    /**
     * Handler para OAuth2 login exitoso - Registra en auditoría
     */
    @Bean
    public AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler() {
        return new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request, 
                                               HttpServletResponse response, 
                                               Authentication authentication) 
                                               throws IOException, ServletException {
                                            
                // ✅ CORREGIR: Obtener el username correcto desde la BD
                String oauthName = authentication.getName(); // Este es el "sub" o ID de Google
                System.out.println("🔍 OAuth2 Success Handler:");
                System.out.println("   authentication.getName(): " + oauthName);
                System.out.println("   authentication.getPrincipal(): " + authentication.getPrincipal().getClass());
                                            
                // Obtener el email u otra info del principal
                String username = oauthName;
                                            
                if (authentication.getPrincipal() instanceof OAuth2User) {
                    OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
                    String email = oauth2User.getAttribute("email");
                    String login = oauth2User.getAttribute("login");
                    
                    System.out.println("   Email: " + email);
                    System.out.println("   Login: " + login);
                    
                    // ✅ Reconstruir el username como lo hicimos en CustomOAuth2UserService
                    // Detectar provider (Google o GitHub)
                    String provider = "google"; // default
                    if (login != null && email == null) {
                        provider = "github";
                    }
                    
                    if ("google".equals(provider) && email != null) {
                        username = "google_" + email;
                    } else if ("github".equals(provider) && login != null) {
                        username = "github_" + login;
                    }
                }
                
                System.out.println("   ✅ Username final para auditoría: " + username);
                
                // Registrar login OAuth2 exitoso
                try {
                    auditoriaService.registrarLoginOAuth2(username, "OAuth2", request);
                    System.out.println("✓ OAUTH2 LOGIN EXITOSO: " + username + " desde " + request.getRemoteAddr());
                } catch (Exception e) {
                    System.err.println("⚠️ Error al registrar auditoría OAuth2: " + e.getMessage());
                    e.printStackTrace();
                }
                
                // Redirigir al dashboard
                response.sendRedirect("/dashboard");
            }
        };
    }

    /**
     * Configuración principal de seguridad
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configurar el UserDetailsService personalizado
            .userDetailsService(customUserDetailsService)
            
            // Configuración de autorización
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/registro", "/css/**", "/js/**", "/error").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/auditoria/**").hasAnyRole("ADMIN", "SUPERVISOR")
                .anyRequest().authenticated()
            )
            
            // Configuración de login tradicional CON AUDITORÍA
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("nombre")
                .passwordParameter("clave")
                .successHandler(authenticationSuccessHandler())
                .failureHandler(customAuthenticationFailureHandler())
                .permitAll()
            )
            
            // Configuración de OAuth2 CON AUDITORÍA
            .oauth2Login(oauth -> oauth
                .loginPage("/login")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(customOAuth2UserService)
                )
                .successHandler(oauth2AuthenticationSuccessHandler())
                .failureUrl("/login?error=oauth")
            )
            
            // Configuración de logout CON AUDITORÍA
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout=true")
                .addLogoutHandler((request, response, authentication) -> {
                    // Registrar logout en auditoría
                    if (authentication != null && authentication.getName() != null) {
                        String username = authentication.getName();
                        try {
                            auditoriaService.registrarLogout(username, request);
                            System.out.println("✓ LOGOUT: " + username);
                        } catch (Exception e) {
                            System.err.println("⚠️ Error al registrar logout: " + e.getMessage());
                        }
                    }
                })
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            
            // Manejo de acceso denegado
            .exceptionHandling(exception -> exception
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    // Registrar acceso denegado en auditoría
                    String username = request.getUserPrincipal() != null 
                        ? request.getUserPrincipal().getName() 
                        : "anonymous";
                    String recurso = request.getRequestURI();
                    
                    try {
                        auditoriaService.registrarAccesoDenegado(username, recurso, request);
                        System.out.println("✗ ACCESO DENEGADO: " + username + " intentó acceder a " + recurso);
                    } catch (Exception e) {
                        System.err.println("⚠️ Error al registrar acceso denegado: " + e.getMessage());
                    }
                    
                    // Redirigir a página de error 403
                    response.sendRedirect("/dashboard?error=acceso_denegado");
                })
            );
            // ← ELIMINADO: .oauth2Client() (ya no es necesario en Spring Security 6.1+)

        return http.build();
    }
}