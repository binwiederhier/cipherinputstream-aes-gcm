
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

public class FullAEADSupportCipherInputStream extends InputStream {
	
	private InputStream in = null;
	private IOException cause = null;
	
	public FullAEADSupportCipherInputStream(InputStream inputStream, Cipher cipher) {
		if ((cipher == null) || (inputStream == null)) {
			throw new NullPointerException();
		}
		CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
		boolean isAEAD = determineAEAD(cipher);
		if (isAEAD) {
			try {
				ByteArrayOutputStream decryptedOutputStream = new ByteArrayOutputStream(); 
				int read = -1;
				byte[] buffer = new byte[1024];
				while (-1 != (read = cipherInputStream.read(buffer))) {
					decryptedOutputStream.write(buffer, 0, read);
				}
				cipherInputStream.close();
				decryptedOutputStream.close();
				this.in = new ByteArrayInputStream(decryptedOutputStream.toByteArray());
			} catch (IOException e) {
				this.cause = e;
			}
		} else {
			this.in = cipherInputStream;
		}
	}
	
	@Override
	public int read() throws IOException {
		beforeAnyOperation();
		return in.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		beforeAnyOperation();
		return in.read(b, off, len);
	}
	
	@Override
	public long skip(long n) throws IOException {
		beforeAnyOperation();
		return in.skip(n);
	}

	@Override
	public int available() throws IOException {
		beforeAnyOperation();
		return in.available();
	}
	
	@Override
	public void close() throws IOException {
		beforeAnyOperation();
		in.close();
	}
	
	@Override
	public synchronized void mark(int readlimit) {
		if (in != null) {
			in.mark(readlimit);
		}
	}
	
	@Override
	public synchronized void reset() throws IOException {
		beforeAnyOperation();
		in.reset();
	}

	@Override
	public boolean markSupported() {
		return (in == null) ? false : in.markSupported();
	}

	protected void beforeAnyOperation() throws IOException {
		if (in == null) {
			throw ((cause == null) ? new IOException("Unknown reason") : cause);
		}
	}
	
	private boolean determineAEAD(Cipher cipher) {
		// Unfortunately javax.crypto.Cipher doesn't have a decent method 
		// to return the cipher mode
		// this implementation is very error-prone
		String[] s = cipher.getAlgorithm().split("/");
		if (s.length < 2) {
			return false;
		}
		String mode = s[1];
		return ((mode.equalsIgnoreCase("CCM")) ||
				(mode.equalsIgnoreCase("EAX")) ||
				(mode.equalsIgnoreCase("GCM")) ||
				(mode.equalsIgnoreCase("OCB")));
	}

}
