package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.Stream;

class C9rDecryptorTest {
	
	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;
	private C9rDecryptor decryptor;
	
	@BeforeEach
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		decryptor = new C9rDecryptor(cryptor, "foo");
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"aaaaBBBBccccDDDDeeeeFFFF",
			"aaaaBBBBccccDDDDeeeeFFF=",
			"aaaaBBBBccccDDDDeeeeFF==",
			"aaaaBBBBccccDDDDeeeeF===",
			"aaaaBBBBccccDDDDeeee====",
			"aaaaBBBB0123456789-_====",
			"aaaaBBBBccccDDDDeeeeFFFFggggHH==",
	})
	public void testValidBase64Pattern(String input) {
		Assertions.assertTrue(C9rDecryptor.BASE64_PATTERN.matcher(input).matches());
	}

	@ParameterizedTest
	@ValueSource(strings = {
			"aaaaBBBBccccDDDDeeee", // too short
			"aaaaBBBBccccDDDDeeeeFFF", // unpadded
			"====BBBBccccDDDDeeeeFFFF", // padding not at end
			"????BBBBccccDDDDeeeeFFFF", // invalid chars
			"conflict aaaaBBBBccccDDDDeeeeFFFF", // only a partial match
			"aaaaBBBBccccDDDDeeeeFFFF conflict", // only a partial match
	})
	public void testInvalidBase64Pattern(String input) {
		Assertions.assertFalse(C9rDecryptor.BASE64_PATTERN.matcher(input).matches());
	}
	
	@Test
	@DisplayName("process canonical filename")
	public void testProcessFullMatch() {
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("helloWorld.txt");
		Node input = new Node(Paths.get("aaaaBBBBccccDDDDeeeeFFFF.c9r"));

		Stream<Node> resultStream = decryptor.process(input);
		Optional<Node> optionalResult = resultStream.findAny();

		Assertions.assertTrue(optionalResult.isPresent());
		Assertions.assertEquals("helloWorld.txt", optionalResult.get().cleartextName);
	}

	@DisplayName("process non-canonical filename")
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"aaaaBBBBcccc_--_11112222 (conflict3000).c9r",
			"(conflict3000) aaaaBBBBcccc_--_11112222.c9r",
			"conflict_aaaaBBBBcccc_--_11112222.c9r",
			"aaaaBBBBcccc_--_11112222_conflict.c9r",
			"____aaaaBBBBcccc_--_11112222.c9r",
			"aaaaBBBBcccc_--_11112222____.c9r",
			"foo_aaaaBBBBcccc_--_11112222_foo.c9r",
			"aaaaBBBBccccDDDDeeeeFFFF___aaaaBBBBcccc_--_11112222----aaaaBBBBccccDDDDeeeeFFFF.c9r",
	})
	public void testProcessPartialMatch(String filename) {
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).then(invocation -> {
			String ciphertext = invocation.getArgument(1);
			if (ciphertext.equals("aaaaBBBBcccc_--_11112222")) {
				return "helloWorld.txt";
			} else {
				throw new AuthenticationFailedException("Invalid ciphertext " + ciphertext);
			}
		});
		Node input = new Node(Paths.get(filename));

		Stream<Node> resultStream = decryptor.process(input);
		Optional<Node> optionalResult = resultStream.findAny();

		Assertions.assertTrue(optionalResult.isPresent());
		Assertions.assertEquals("helloWorld.txt", optionalResult.get().cleartextName);
	}

	@DisplayName("process filename without ciphertext")
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"foo.bar",
			"foo.c9r",
			"aaaaBBBB$$$$DDDDeeeeFFFF.c9r",
			"aaaaBBBBxxxxDDDDeeeeFFFF.c9r",
	})
	public void testProcessNoMatch(String filename) {
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenThrow(new AuthenticationFailedException("Invalid ciphertext."));
		Node input = new Node(Paths.get(filename));

		Stream<Node> resultStream = decryptor.process(input);
		Optional<Node> optionalResult = resultStream.findAny();

		Assertions.assertFalse(optionalResult.isPresent());
	}

}