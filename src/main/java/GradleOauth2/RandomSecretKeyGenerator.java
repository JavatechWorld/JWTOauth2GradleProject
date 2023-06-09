package GradleOauth2;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class RandomSecretKeyGenerator {
    
	public String ranValue() {
		String secretKey = null;
        try {
            // Generate a random secret key
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            byte[] keyBytes = new byte[32];
            secureRandom.nextBytes(keyBytes);

            // Encode the key as a Base64 string
            secretKey = Base64.getEncoder().encodeToString(keyBytes); 
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Error: Failed to generate random secret key.");
        }
		//return secretKey;
		return secretKey;
    }
}
