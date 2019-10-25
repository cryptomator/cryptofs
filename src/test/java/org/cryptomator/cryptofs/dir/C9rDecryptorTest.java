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
		Mockito.when(fileNameCryptor.decryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).then(invocation -> {
			String ciphertext = invocation.getArgument(1);
			if (ciphertext.equals("aaaaBBBBccccDDDDeeeeFFFF")) {
				return "FFFFeeeeDDDDccccBBBBaaaa";
			} else {
				throw new AuthenticationFailedException("Invalid ciphertext " + ciphertext);
			}
		});
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
		NodeNames input = new NodeNames(Paths.get("aaaaBBBBccccDDDDeeeeFFFF.c9r"));

		Stream<NodeNames> resultStream = decryptor.process(input);
		Optional<NodeNames> optionalResult = resultStream.findAny();

		Assertions.assertTrue(optionalResult.isPresent());
		Assertions.assertEquals("FFFFeeeeDDDDccccBBBBaaaa", optionalResult.get().cleartextName);
	}

	@DisplayName("process non-canonical filename")
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"aaaaBBBBccccDDDDeeeeFFFF (conflict3000).c9r",
			"(conflict3000) aaaaBBBBccccDDDDeeeeFFFF.c9r",
			"conflict_aaaaBBBBccccDDDDeeeeFFFF.c9r",
			"aaaaBBBBccccDDDDeeeeFFFF_conflict.c9r",
			"_aaaaBBBBccccDDDDeeeeFFFF.c9r",
			"aaaaBBBBccccDDDDeeeeFFFF_.c9r",
	})
	public void testProcessPartialMatch(String filename) {
		NodeNames input = new NodeNames(Paths.get(filename));

		Stream<NodeNames> resultStream = decryptor.process(input);
		Optional<NodeNames> optionalResult = resultStream.findAny();

		Assertions.assertTrue(optionalResult.isPresent());
		Assertions.assertEquals("FFFFeeeeDDDDccccBBBBaaaa", optionalResult.get().cleartextName);
	}

	@DisplayName("process filename without ciphertext")
	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {
			"foo.bar",
			"foo.c9r",
			"aaaaBBBB????DDDDeeeeFFFF.c9r",
			"aaaaBBBBxxxxDDDDeeeeFFFF.c9r",
	})
	public void testProcessNoMatch(String filename) {
		NodeNames input = new NodeNames(Paths.get(filename));

		Stream<NodeNames> resultStream = decryptor.process(input);
		Optional<NodeNames> optionalResult = resultStream.findAny();

		Assertions.assertFalse(optionalResult.isPresent());
	}

}