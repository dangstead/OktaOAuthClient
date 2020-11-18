package com.okta.spring.OktaOAuthClient;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClaimsLogger {
	
	private static final Logger logger = LoggerFactory.getLogger(ClaimsLogger.class);
	
	public static void logClaims(Map<String, Object> claims) {
		logHeader();
		for (String claimKey : claims.keySet()) {
			Object object = claims.get(claimKey);
			if (object instanceof String) {
				String value = (String) object;
				logClaim(claimKey, value);
			} else if (object instanceof Instant) {
				Instant instant = (Instant) object;
				logClaim(claimKey, instant.toString());
			} else if (claimKey.equalsIgnoreCase("address")) {
				@SuppressWarnings("unchecked")
				Map<String, String> map = (LinkedHashMap<String, String>) object;
				for (String addressKey : map.keySet()) {
					String addressValue = map.get(addressKey);
					logClaim("addr:"+addressKey, addressValue);
				}
			}
		}
	}
	
	private static void logHeader() {
		logger.info("Logging All Claims");
	}

	public static void logClaim(String key, String value) {
		String msg = String.format("%-20s : %-20s", key, value);
		logger.info(msg);
	}

}
