package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.LongFileNameProvider;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.stream.Stream;

class C9SInflatorTest {

	private LongFileNameProvider longFileNameProvider;
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;
	private C9sInflator inflator;

	@BeforeEach
	public void setup() {
		longFileNameProvider = Mockito.mock(LongFileNameProvider.class);
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		inflator = new C9sInflator(longFileNameProvider, cryptor, "foo");
	}
	
	@Test
	public void inflateDeflated() throws IOException {
		Node deflated = new Node(Paths.get("foo.c9s"));
		Mockito.when(longFileNameProvider.inflate(deflated.ciphertextPath)).thenReturn("foo.c9r");
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenReturn("hello world.txt");
		
		Stream<Node> result = inflator.process(deflated);
		Node inflated = result.findAny().get();

		Assertions.assertEquals("foo", inflated.extractedCiphertext);
		Assertions.assertEquals("hello world.txt", inflated.cleartextName);
	}

	@Test
	public void inflateUninflatableDueToIOException() throws IOException {
		Node deflated = new Node(Paths.get("foo.c9s"));
		Mockito.when(longFileNameProvider.inflate(deflated.ciphertextPath)).thenThrow(new IOException("peng!"));
		
		Stream<Node> result = inflator.process(deflated);
		Assertions.assertFalse(result.findAny().isPresent());
	}

	@Test
	public void inflateUninflatableDueToInvalidCiphertext() throws IOException {
		Node deflated = new Node(Paths.get("foo.c9s"));
		Mockito.when(longFileNameProvider.inflate(deflated.ciphertextPath)).thenReturn("foo.c9r");
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.eq("foo"), Mockito.any())).thenThrow(new AuthenticationFailedException("peng!"));

		Stream<Node> result = inflator.process(deflated);
		Assertions.assertFalse(result.findAny().isPresent());
	}

}