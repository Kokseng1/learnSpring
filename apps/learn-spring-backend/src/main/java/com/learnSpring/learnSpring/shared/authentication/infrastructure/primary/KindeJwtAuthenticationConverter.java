package com.learnSpring.learnSpring.shared.authentication.infrastructure.primary;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import com.learnSpring.learnSpring.shared.authentication.application.AuthenticatedUser;

import io.micrometer.common.lang.NonNull;

public class KindeJwtAuthenticationConverter implements org.springframework.core.convert.converter.Converter<Jwt, AbstractAuthenticationToken>{
    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt source) {
        return new JwtAuthenticationToken(source, 
            Stream.concat(new JwtGrantedAuthoritiesConverter().convert(source).stream(), extractResourceRoles(source).stream()).collect(Collectors.toSet()));
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        return AuthenticatedUser.extractRolesFromToken(jwt).stream()
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toSet());
    }
}
