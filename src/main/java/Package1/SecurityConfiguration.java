package Package1;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

@Configuration
public class SecurityConfiguration {

    // Injecting a custom AccessDeniedHandler bean to handle access denied scenarios
    @Autowired
    private AccessDeniedHandler customAccessDeniedHandler;

    // Defining the security filter chain to configure security settings
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Configuring request authorization
            .authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                    // Allowing access to login and error pages without authentication
                    .requestMatchers("/login", "/error").permitAll()
                    // Restricting access to /admin to users with the ADMIN role
                    .requestMatchers("/admin").hasRole("ADMIN")
                    //Give All permissions to a particular role requestMatchers("/**").hasRole("Role")
//                    Give All permissions to Every Role ..requestMatchers("/**").permitAll()
                    
                    // Requiring authentication for all other requests
                    .anyRequest().authenticated()
            )
            // Configuring form-based login
            .formLogin(formLogin ->
                formLogin
                    // Setting the custom login page
                    .loginPage("/login")
                    // Permitting all users to access the login page
                    .permitAll()
                    // Redirecting to the home page after successful login
                    .defaultSuccessUrl("/")
            )
            // Configuring logout behavior
            .logout(logout ->
                logout
                    // Setting the URL for logging out
                    .logoutUrl("/logout")
                    // Invalidating the HTTP session on logout
                    .invalidateHttpSession(true)
                    // Deleting the session cookie on logout
                    .deleteCookies("JSESSIONID")
            )
            // Configuring exception handling for access denied scenarios
            .exceptionHandling(exceptionHandling ->
                exceptionHandling
                    // Using the custom AccessDeniedHandler for handling access denied errors
                    .accessDeniedHandler(customAccessDeniedHandler)
            )
            // Configuring HTTP headers to prevent caching of responses
            .headers(headers ->
                headers
                    // Adding headers to prevent caching of sensitive pages
                    .addHeaderWriter(new StaticHeadersWriter(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate"))
                    .addHeaderWriter(new StaticHeadersWriter(HttpHeaders.PRAGMA, "no-cache"))
                    .addHeaderWriter(new StaticHeadersWriter(HttpHeaders.EXPIRES, "0"))
            );
        // Building and returning the SecurityFilterChain bean
        return http.build();
    }

    // Defining an in-memory UserDetailsService for user authentication
    @Bean
    public UserDetailsService userDetailsService() {
        // Creating a user with USER role
        UserDetails user1 = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();

        // Creating a user with ADMIN role
        UserDetails user2 = User.withDefaultPasswordEncoder()
            .username("Ismail")
            .password("Mansuri")
            .roles("ADMIN")
            .build();

        // Returning an InMemoryUserDetailsManager with the defined users
        return new InMemoryUserDetailsManager(user1, user2);
    }
}
