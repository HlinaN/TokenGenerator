package ebirrToken;

import org.apache.synapse.commons.json.JsonUtil;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AesEncryptMediator extends AbstractMediator {

	@Override
	public boolean mediate(MessageContext context) {
	    try {
	        // --- Step 1: Read secret from context ---
	        String secret = (String) context.getProperty("secret");
	        if (secret == null || secret.isEmpty()) {
	            context.setProperty("encryptionError", "Missing 'secret' property");
	            return false;
	        }

	        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
	        int keyLength = keyBytes.length;

	        // --- Step 2: Determine AES algorithm based on key length ---
	        String algo;
	        if (keyLength == 16) algo = "AES/CBC/PKCS5Padding"; // AES-128
	        else if (keyLength == 24) algo = "AES/CBC/PKCS5Padding"; // AES-192
	        else if (keyLength == 32) algo = "AES/CBC/PKCS5Padding"; // AES-256
	        else {
	            context.setProperty("encryptionError", "Invalid AES key length");
	            return false;
	        }

	        // --- Step 3: Get payload from body ---
	        org.apache.axis2.context.MessageContext axis2MessageContext = ((Axis2MessageContext) context).getAxis2MessageContext();
	        String payload;
	        if (JsonUtil.hasAJsonPayload(axis2MessageContext)) {
	            payload = JsonUtil.jsonPayloadToString(axis2MessageContext);
	        } else {
	            payload = context.getEnvelope().getBody().getFirstElement().toString();
	        }

	        log.info("Plaintext payload: " + payload);

	        // --- Step 4: Encrypt JSON string using AES-CBC ---
	        byte[] ivBytes = new byte[16];
	        SecureRandom random = new SecureRandom();
	        random.nextBytes(ivBytes);
	        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

	        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "AES");

	        Cipher cipher = Cipher.getInstance(algo);
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
	        byte[] plaintextBytes = payload.getBytes(StandardCharsets.UTF_8);
	        byte[] ciphertextBytes = cipher.doFinal(plaintextBytes);

	        // --- Step 5: Concatenate IV + Ciphertext, then Base64 encode ---
	        byte[] combined = new byte[ivBytes.length + ciphertextBytes.length];
	        System.arraycopy(ivBytes, 0, combined, 0, ivBytes.length);
	        System.arraycopy(ciphertextBytes, 0, combined, ivBytes.length, ciphertextBytes.length);
	        String payloadBase64 = Base64.getEncoder().encodeToString(combined);

	        // --- Step 6: Build JWT { data: base64(iv + ciphertext) } ---
	        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	        String payloadJson = "{\"data\":\"" + payloadBase64 + "\"}";

	        String encodedHeader = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
	        String encodedPayload = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

	        String signingInput = encodedHeader + "." + encodedPayload;
	        String signature = hmacSha256(signingInput, secret); // Same key used for HMAC

	        String jwt = signingInput + "." + signature;

	        // --- Step 7: Set to context ---
	        context.setProperty("withdrawRequest", jwt);
	        log.info("Generated JWT: " + jwt);

	        return true;

	    } catch (Exception e) {
	        context.setProperty("encryptionError", e.getMessage());
	        log.error("Encryption or JWT creation failed", e);
	        return false;
	    }
	}
	
	private byte[] padKey(byte[] key, int length) {
	    byte[] padded = new byte[length];
	    int len = Math.min(key.length, length);
	    System.arraycopy(key, 0, padded, 0, len);
	    return padded;
	}

	private String base64UrlEncode(byte[] input) {
	    return Base64.getUrlEncoder().withoutPadding().encodeToString(input);
	}

	private String hmacSha256(String data, String key) throws Exception {
	    SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
	    Mac mac = Mac.getInstance("HmacSHA256");
	    mac.init(signingKey);
	    byte[] rawHmac = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
	    return base64UrlEncode(rawHmac);
	}
}

