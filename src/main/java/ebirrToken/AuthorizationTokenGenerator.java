package ebirrToken;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class AuthorizationTokenGenerator extends AbstractMediator {

    @Override
    public boolean mediate(MessageContext context) {
        try {
            // Step 1: Read properties from context
            String username = (String) context.getProperty("username");
            String timestamp = (String) context.getProperty("timestamp");
            String partnerKey = (String) context.getProperty("partnerKey");

            if (username == null || timestamp == null || partnerKey == null) {
                context.setProperty("authError", "Missing username, timestamp, or partnerKey");
                return false;
            }

            // Step 2: Concatenate username + timestamp
            String input = username + timestamp;

            // Step 3: SHA-512 hashing
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] hashBytes = sha512.digest(input.getBytes(StandardCharsets.UTF_8));

            // Step 4: Convert hash to hex
            StringBuilder hexBuilder = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexBuilder.append('0');
                hexBuilder.append(hex);
            }
            String hexHash = hexBuilder.toString();

            // Step 5: Create "key:value" string and Base64 encode
            String rawToken = partnerKey + ":" + hexHash;
            String encodedToken = Base64.getEncoder().encodeToString(rawToken.getBytes(StandardCharsets.UTF_8));

            // Step 6: Set token as a property
            context.setProperty("Authorization", encodedToken);

            // Optional: Log the result
            log.info("Generated Authorization Token: " + encodedToken);

            return true;

        } catch (Exception e) {
            context.setProperty("authError", e.getMessage());
            log.error("Token generation failed", e);
            return false;
        }
    }
}
