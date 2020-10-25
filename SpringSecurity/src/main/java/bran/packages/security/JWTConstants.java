package bran.packages.security;

public class JWTConstants {

	static final String SECRET_KEY = "bmw e39";

    static final String AUTHORIZATION_HEADER = "Authorization";

    static final String TOKEN_PREFIX = "Bearer ";

    static final long EXPIRATION_TIME = 900000; // 15 minutes

    private JWTConstants() {}
	
}
