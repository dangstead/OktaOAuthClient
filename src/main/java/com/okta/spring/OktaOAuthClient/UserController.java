package com.okta.spring.OktaOAuthClient;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@RequestMapping(value = "/claims", method = RequestMethod.GET)
	public ResponseEntity<?> claimsResponse(OAuth2AuthenticationToken authentication) {
		ClaimsLogger.logClaim("Name", authentication.getName());
		DefaultOidcUser user = (DefaultOidcUser) authentication.getPrincipal();
		OidcUserInfo userInfo = user.getUserInfo();
		
		// Get predefined claims by getter method
		ClaimsLogger.logClaim("Email", user.getEmail());
		
		// Get claim by claim name
		String profile = userInfo.getClaimAsString("profile");
		ClaimsLogger.logClaim("Profile", profile);
		
		// Log all claims including custom ones
		Map<String, Object> claims = Collections.unmodifiableMap(userInfo.getClaims());
		ClaimsLogger.logClaims(claims);
		
		// Return as JSON object
		return new ResponseEntity<Object>(claims, HttpStatus.OK);
	}

	@RequestMapping(value = "/idToken", method = RequestMethod.GET)
	public ResponseEntity<?> idTokenResponse(OAuth2AuthenticationToken authentication) {
		DefaultOidcUser user = (DefaultOidcUser) authentication.getPrincipal();
		String idToken = user.getIdToken().getTokenValue();
		return new ResponseEntity<Object>(idToken, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/accessToken", method = RequestMethod.GET)
	public ResponseEntity<?> accessTokenResponse(OAuth2AuthenticationToken authentication) {
		
		OAuth2AuthorizedClient client =
				authorizedClientService.loadAuthorizedClient(
			    		authentication.getAuthorizedClientRegistrationId(),
			    		authentication.getName());

		String accessToken = client.getAccessToken().getTokenValue();
		return new ResponseEntity<Object>(accessToken, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/grantedAuthorities", method = RequestMethod.GET)
	public ResponseEntity<?> grantedAuthoritiesResponse(OAuth2AuthenticationToken authentication) {
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		return new ResponseEntity<Object>(authorities, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/simpleGrantedAuthorities", method = RequestMethod.GET)
	public ResponseEntity<?> simpleGrantedAuthoritiesResponse(OAuth2AuthenticationToken authentication) {
		Collection<SimpleGrantedAuthority> simpleGrantedAuthorities = getSimpleGrantedAuthorities(authentication);
		return new ResponseEntity<Object>(simpleGrantedAuthorities, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/groups", method = RequestMethod.GET)
	public ResponseEntity<?> groupsResponse(OAuth2AuthenticationToken authentication) {
		Collection<SimpleGrantedAuthority> simpleGrantedAuthorities = getSimpleGrantedAuthorities(authentication);
		List<String> groups = getGroups(simpleGrantedAuthorities);
		return new ResponseEntity<Object>(groups, HttpStatus.OK);
	}
	
	@RequestMapping(value = "/scopes", method = RequestMethod.GET)
	public ResponseEntity<?> scopesResponse(OAuth2AuthenticationToken authentication) {
		Collection<SimpleGrantedAuthority> simpleGrantedAuthorities = getSimpleGrantedAuthorities(authentication);
		List<String> scopes = getScopes(simpleGrantedAuthorities);
		return new ResponseEntity<Object>(scopes, HttpStatus.OK);
	}
	
	private List<String> getGroups(Collection<SimpleGrantedAuthority> simpleGrantedAuthorities) {
		List<String> groups = new ArrayList<String>();
		Iterator<SimpleGrantedAuthority> iterator = simpleGrantedAuthorities.iterator();
		while (iterator.hasNext()) {
			SimpleGrantedAuthority ga = iterator.next();
			String authority = ga.getAuthority();
			if (!authority.startsWith("SCOPE_")) {
				groups.add(authority);
			}
		}
		return groups;
	}

	private List<String> getScopes(Collection<SimpleGrantedAuthority> simpleGrantedAuthorities) {
		List<String> scopes = new ArrayList<String>();
		Iterator<SimpleGrantedAuthority> iterator = simpleGrantedAuthorities.iterator();
		while (iterator.hasNext()) {
			SimpleGrantedAuthority ga = iterator.next();
			String authority = ga.getAuthority();
			if (authority.startsWith("SCOPE_")) {
				scopes.add(authority);
			}
		}
		return scopes;
	}

	private Collection<SimpleGrantedAuthority> getSimpleGrantedAuthorities(OAuth2AuthenticationToken authentication) {
		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		Collection<SimpleGrantedAuthority> simpleGrantedAuthorities = new ArrayList<SimpleGrantedAuthority>();
		
		Iterator<GrantedAuthority> iterator = authorities.iterator();
		while (iterator.hasNext()) {
			GrantedAuthority ga = iterator.next();
			if (ga instanceof SimpleGrantedAuthority) {
				simpleGrantedAuthorities.add((SimpleGrantedAuthority) ga);
			}
		}
		
		return simpleGrantedAuthorities;
	}
	
	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

}
