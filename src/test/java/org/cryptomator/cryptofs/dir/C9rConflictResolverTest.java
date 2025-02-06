package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

public class C9rConflictResolverTest {

	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;
	private VaultConfig vaultConfig;
	private C9rConflictResolver conflictResolver;

	@BeforeEach
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		vaultConfig = Mockito.mock(VaultConfig.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(vaultConfig.getShorteningThreshold()).thenReturn(84); // results in max cleartext size = 44
		conflictResolver = new C9rConflictResolver(cryptor, "foo", vaultConfig);
	}
	
	@Test
	public void testResolveNonConflictingNode() {
		Node unresolved = new Node(Paths.get("foo.c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertSame(unresolved, resolved);
	}

	@ParameterizedTest
	@ValueSource(strings = {"._foo.c9r", ".foo.c9r"})
	public void testResolveHiddenNode(String filename) {
		Node unresolved = new Node(Paths.get(filename));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Assertions.assertFalse(result.findAny().isPresent());
	}

	@Test
	public void testResolveConflictingFileByChoosingNewName(@TempDir Path dir) throws IOException {
		Files.createFile(dir.resolve("foo (Created by Alice).c9r"));
		Files.createFile(dir.resolve("foo.c9r"));
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (Created by Alice).c9r"));
		unresolved.cleartextName = "bar.txt";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("baz.c9r", resolved.fullCiphertextFileName);
		Assertions.assertEquals("bar (Created by Alice).txt", resolved.cleartextName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

	@Test
	public void testResolveConflictingFileByAddingNumericSuffix(@TempDir Path dir) throws IOException {
		Files.createFile(dir.resolve("foo (Created by Alice).c9r"));
		Files.createFile(dir.resolve("foo.c9r"));
		Files.createFile(dir.resolve("baz.c9r")); // resolved name already occupied, try cux next!
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz").thenReturn("qux");
		Node unresolved = new Node(dir.resolve("foo (Created by Alice).c9r"));
		unresolved.cleartextName = "bar.txt";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("qux.c9r", resolved.fullCiphertextFileName);
		Assertions.assertEquals("bar (1).txt", resolved.cleartextName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

	@Test
	public void testResolveConflictingFileByChoosingNewLengthLimitedName(@TempDir Path dir) throws IOException {
		Files.createFile(dir.resolve("foo (Created by Alice on 2024-01-31).c9r"));
		Files.createFile(dir.resolve("foo.c9r"));
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (Created by Alice on 2024-01-31).c9r"));
		unresolved.cleartextName = "this is a rather long file name.txt";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("baz.c9r", resolved.fullCiphertextFileName);
		Assertions.assertEquals("this is a rather lon (Created by Alice o.txt", resolved.cleartextName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

	@Test
	public void testResolveConflictFailedAlternativeNamesReserved(@TempDir Path dir) throws IOException {
		Files.createFile(dir.resolve("foo (Created by Alice on 2024-01-31).c9r"));
		Files.createFile(dir.resolve("foo.c9r"));
		Files.createFile(dir.resolve("baz.c9r"));
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (Created by Alice on 2024-01-31).c9r"));
		unresolved.cleartextName = "this is a rather long file name.txt";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Assertions.assertTrue(result.findAny().isEmpty());
		Assertions.assertTrue(Files.exists(unresolved.ciphertextPath));
		Mockito.verify(fileNameCryptor, Mockito.times(10)).encryptFilename(Mockito.any(), Mockito.any(), Mockito.any());
	}

	@Test
	public void testResolveConflictingFileTrivially(@TempDir Path dir) throws IOException {
		Files.createFile(dir.resolve("foo (1).c9r"));
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("foo.c9r", resolved.fullCiphertextFileName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

	@Test
	public void testResolveConflictingDirTrivially(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.write(dir.resolve("foo (1).c9r/dir.c9r"), "dirid".getBytes());
		Files.write(dir.resolve("foo.c9r/dir.c9r"), "dirid".getBytes());
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("foo.c9r", resolved.fullCiphertextFileName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

	@Test
	public void testResolveConflictingSymlinkTrivially(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.write(dir.resolve("foo (1).c9r/symlink.c9r"), "linktarget".getBytes());
		Files.write(dir.resolve("foo.c9r/symlink.c9r"), "linktarget".getBytes());
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertNotEquals(unresolved, resolved);
		Assertions.assertEquals("foo.c9r", resolved.fullCiphertextFileName);
		Assertions.assertTrue(Files.exists(resolved.ciphertextPath));
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
	}

}