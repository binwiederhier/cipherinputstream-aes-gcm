// March 2014, Philipp C. Heckel

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class BouncyCastleCISIssue {
	private static final SecureRandom secureRandom = new SecureRandom();
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String args[]) throws Exception {
		System.out.println("----------------------------------------------------------------------------------");

		testBouncyCastleCipherInputStreamWithAesGcmLongPlaintext();

		System.out.println("----------------------------------------------------------------------------------");
	}
	
	public static void testBouncyCastleCipherInputStreamWithAesGcmLongPlaintext() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = createRandomArray(4080); // <<<< 4080 bytes fails, 4079 bytes works! 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		KeyParameter secretKey = new KeyParameter(randomKey);		
		cipher.init(false, new AEADParameters(secretKey, 128, randomIv));
		
		try {
			readFromStream(new org.bouncycastle.crypto.io.CipherInputStream(new ByteArrayInputStream(originalCiphertext), cipher));
			System.out.println("org.bouncycastle.crypto.io.CipherInputStream:    OK, throws no exception");						
		}
		catch (ArrayIndexOutOfBoundsException e) {
			System.out.println("org.bouncycastle.crypto.io.CipherInputStream:    NOT OK, throws the following exception:");
			e.printStackTrace();
		}
	}	

	private static byte[] readFromStream(InputStream inputStream) throws IOException {
		ByteArrayOutputStream decryptedPlaintextOutputStream = new ByteArrayOutputStream(); 
		
		int read = -1;
		byte[] buffer = new byte[16];
		
		while (-1 != (read = inputStream.read(buffer))) {
			decryptedPlaintextOutputStream.write(buffer, 0, read);
		}
		
		inputStream.close();
		decryptedPlaintextOutputStream.close();
		
		return decryptedPlaintextOutputStream.toByteArray();  		
	}
	
	private static byte[] encryptWithAesGcm(byte[] plaintext, byte[] randomKeyBytes, byte[] randomIvBytes) throws IOException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {

		SecretKey randomKey = new SecretKeySpec(randomKeyBytes, "AES");
		
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, randomKey, new IvParameterSpec(randomIvBytes));
		
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
		
		cipherOutputStream.write(plaintext);
		cipherOutputStream.close();
		
		return byteArrayOutputStream.toByteArray();
	}
	
	private static byte[] createRandomArray(int size) {
		byte[] randomByteArray = new byte[size];
		secureRandom.nextBytes(randomByteArray);

		return randomByteArray;
	}	
}

