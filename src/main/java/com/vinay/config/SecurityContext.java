package com.vinay.config;

public interface SecurityContext {
	
	public static final String JWT_HEADER = "Authorization";
	
	/** The JWT signing key, read from Google Secret Manager on first use. */
	public static String jwtKey() throws java.io.IOException {
		return JwtKeyProvider.getJwtKey();
	}

}
