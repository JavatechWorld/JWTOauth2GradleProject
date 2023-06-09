package GradleOauth2;

import java.util.Date;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public class ValidationHelper {

	JwtGeneratorValidator jwtgenval = new JwtGeneratorValidator();

	public  boolean validateReturn(Authentication headers) {
		Token jwtToken = null;
		if (headers != null && headers.getDetails() instanceof Token) {
			jwtToken = (Token) headers.getDetails();
		}
		if (jwtToken != null && jwtToken.getExpiryDate().after(new Date()) 
				&&  jwtgenval.validateToken(jwtToken.getToken())) {
			return true;
		} else {
			return false;
		}
	}
	
	public  void  clearData(Authentication headers) {
		
		if (headers != null && headers.getDetails() instanceof Token) {
			Token jwtToken = new Token("", new Date());
       	 ((OAuth2AuthenticationToken) headers).setDetails(jwtToken);
		}
		
	}

}
