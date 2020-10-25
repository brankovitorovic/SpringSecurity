package bran.packages.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

	private final UserDetailsService userDetailsService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
		super(authenticationManager);
		this.userDetailsService = userDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String authorizationHeader = request.getHeader(JWTConstants.AUTHORIZATION_HEADER);

		System.out.println("JWTAuthorizationFIlter line: 40");

		if (authorizationHeader == null || !authorizationHeader.startsWith(JWTConstants.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		SecurityContextHolder.getContext().setAuthentication(getAuthenticationToken(authorizationHeader));
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthenticationToken(String authorizationHeader) {

		String username = JWT.require(Algorithm.HMAC512(JWTConstants.SECRET_KEY)).build()
				.verify(authorizationHeader.replace(JWTConstants.TOKEN_PREFIX, "")).getSubject();

		UserDetails userDetails = userDetailsService.loadUserByUsername(username);

		return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(),
				userDetails.getAuthorities());
	}

}
