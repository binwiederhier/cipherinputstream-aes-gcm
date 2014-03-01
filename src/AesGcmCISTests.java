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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.io.InvalidCipherTextIOException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

public class AesGcmCISTests {
	private static final SecureRandom secureRandom = new SecureRandom();
	
	static {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public static void main(String args[]) throws Exception {
		System.out.println("-----------------------------------------------------------------");

		testJavaxCipherWithAesGcm();
		testJavaxCipherInputStreamWithAesGcm();
		testJavaxCipherInputStreamWithAesGcmFixed();
		testBouncyCastleCipherInputStreamWithAesGcm();

		System.out.println("-----------------------------------------------------------------");
	}
	
	public static void testJavaxCipherWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 		
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$			
		
		// Decrypt with regular CipherInputStream (from JDK6/7)
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			cipher.doFinal(alteredCiphertext);		
			//  ^^^^^^ INTERESTING PART ^^^^^^	
			//
			//  The GCM implementation in BouncyCastle and the Cipher class in the javax.crypto package 
			//  behave correctly: A BadPaddingException is thrown when we try to decrypt the altered ciphertext.
			//  The code below is not executed.
			//
			
			System.out.println("javac.crypto.Cipher:                             NOT OK");
		}
		catch (BadPaddingException e) {		
			System.out.println("javac.crypto.Cipher:                             OK");
		}
	}	
	
	public static void testJavaxCipherInputStreamWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 		
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$			
		
		// Decrypt with regular CipherInputStream (from JDK6/7)
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			byte[] decryptedPlaintext = readFromStream(new javax.crypto.CipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//                                         ^^^^^^^^ INTERESTING PART ^^^^^^^^	
			//
			//  The regular CipherInputStream in the javax.crypto package simply ignores BadPaddingExceptions
			//  and doesn't pass them to the application. Tampering with the ciphertext does thereby not throw  
			//  a MAC verification error. The code below is actually executed. The two plaintexts do not match!
			//  The decrypted payload is "Confirm 900$ pay" (not: "Confirm 100$ pay")
			//

			System.out.println("javac.crypto.CipherInputStream:                  NOT OK");
			System.out.println("  Original plaintext:                            " + new String(originalPlaintext, "ASCII"));
			System.out.println("  Decrypted plaintext:                           " + new String(decryptedPlaintext, "ASCII"));
		}
		catch (Exception e) {
			System.out.println("javac.crypto.CipherInputStream:                  OK");
		}
	}	

	public static void testJavaxCipherInputStreamWithAesGcmFixed() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$
		
		// Decrypt with "fixed" JDK implementation of CipherInputStream
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(randomKey, "AES"), new IvParameterSpec(randomIv));
		
		try {
			readFromStream(new QuickFixDemoCipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));		
			//             ^^^^^^^ INTERESTING PART ^^^^^^^^	
			//
			//  When Cipher.doFinal() is called in the QuickFixDemoCipherInputStream, a BadPaddingException
			//  is thrown and passed to the application wrapped in a InvalidCiphertextIOException (inner 
			//  class in QuickFixDemoCipherInputStream). This way, MAC verification errors can be detected. 
			//  The code below is not executed.
			//
			
			System.out.println("QuickFixDemoCipherInputStream:                   NOT OK");				
		}
		catch (QuickFixDemoCipherInputStream.QuickFixDemoInvalidCipherTextIOException e) {
			System.out.println("QuickFixDemoCipherInputStream:                   OK");				
		}
	}
	
	public static void testBouncyCastleCipherInputStreamWithAesGcm() throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		// Encrypt (not interesting in this example)
		byte[] randomKey = createRandomArray(16);
		byte[] randomIv = createRandomArray(16);		
		byte[] originalPlaintext = "Confirm 100$ pay".getBytes("ASCII"); 	
		byte[] originalCiphertext = encryptWithAesGcm(originalPlaintext, randomKey, randomIv);
		
		// Attack / alter ciphertext (an attacker would do this!) 
		byte[] alteredCiphertext = Arrays.clone(originalCiphertext);		
		alteredCiphertext[8] = (byte) (alteredCiphertext[8] ^ 0x08); // <<< Change 100$ to 900$
		
		// Decrypt with BouncyCastle implementation of CipherInputStream
		AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine()); 
		KeyParameter secretKey = new KeyParameter(createRandomArray(16));		
		cipher.init(false, new AEADParameters(secretKey, 128, randomIv));
		
		try {
			readFromStream(new org.bouncycastle.crypto.io.CipherInputStream(new ByteArrayInputStream(alteredCiphertext), cipher));
			//             ^^^^^^^^^^^^^^^ INTERESTING PART ^^^^^^^^^^^^^^^^	
			//
			//  The BouncyCastle implementation of the CipherInputStream detects MAC verification errors and
			//  throws a InvalidCipherTextIOException if an error occurs. Nice! A more or less minor issue
			//  however is that it is incompatible with the standard JCE Cipher class from the javax.crypto 
			//  package. The new interface AEADBlockCipher must be used. The code below is not executed.		

			System.out.println("org.bouncycastle.crypto.io.CipherInputStream:    NOT OK");						
		}
		catch (InvalidCipherTextIOException e) {
			System.out.println("org.bouncycastle.crypto.io.CipherInputStream:    OK");						
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

