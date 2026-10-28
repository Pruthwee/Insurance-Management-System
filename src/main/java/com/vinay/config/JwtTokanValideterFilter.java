package com.vinay.config;

import java.io.IOException;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * JWT validation filter.
 *
 * The JWT signing key is no longer hard-coded; it is retrieved at runtime from
 * Google Cloud Secret Manager via {@link GcpSecretManagerService}.
 */
public class JwtTokanValideterFilter extends OncePerRequestFilter {

    private final GcpSecretManagerService gcpSecretManagerService;

    public JwtTokanValideterFilter(GcpSecretManagerService gcpSecretManagerService) {
        this.gcpSecretManagerService = gcpSecretManagerService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String jwt = request.getHeader(SecurityContext.JWT_HEADER);

        if (jwt != null) {
            try {
                jwt = jwt.substring(7);

                // Retrieve the JWT signing key from GCP Secret Manager (loaded at startup)
                SecretKey key = Keys.hmacShaKeyFor(
                        gcpSecretManagerService.getJwtSecretKey().getBytes());

                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(jwt)
                        .getBody();

                String username = String.valueOf(claims.get("username"));
                String authorities = String.valueOf(claims.get("authorities"));

                List<GrantedAuthority> authorityList =
                        AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(username, null, authorityList);

                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                throw new BadCredentialsException("Invalid Tokan");
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/signIn");
    }
}
