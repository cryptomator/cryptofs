package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.VaultConfig;
import org.cryptomator.cryptofs.event.ConflictResolutionFailedEvent;
import org.cryptomator.cryptofs.event.ConflictResolvedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.mockito.Mockito.verify;

public class C9rConflictResolverTest {

	private static final String DIR_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"; // 36 chars, i.e. MAX_DIR_ID_LENGTH
	private static final String OTHER_DIR_ID = "11111111-2222-3333-4444-555555555555";

	private Cryptor cryptor;
	private FileNameCryptor fileNameCryptor;
	private VaultConfig vaultConfig;
	private Consumer<FilesystemEvent> eventConsumer = Mockito.mock(Consumer.class);
	private Path cleartextPath = Mockito.mock(Path.class, "/clear/text/path/");
	private C9rConflictResolver conflictResolver;

	@BeforeEach
	public void setup() {
		cryptor = Mockito.mock(Cryptor.class);
		fileNameCryptor = Mockito.mock(FileNameCryptor.class);
		vaultConfig = Mockito.mock(VaultConfig.class);
		Mockito.when(cryptor.fileNameCryptor()).thenReturn(fileNameCryptor);
		Mockito.when(vaultConfig.getShorteningThreshold()).thenReturn(84); // results in max cleartext size = 44
		Mockito.when(cleartextPath.resolve(Mockito.anyString())).thenReturn(cleartextPath);
		conflictResolver = new C9rConflictResolver(cryptor, "foo", vaultConfig, eventConsumer, cleartextPath);
	}

	@Test
	public void testResolveNonConflictingNode() {
		Node unresolved = new Node(Path.of("foo.c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertSame(unresolved, resolved);
	}

	@ParameterizedTest
	@ValueSource(strings = {"._foo.c9r", ".foo.c9r"})
	public void testResolveHiddenNode(String filename) {
		Node unresolved = new Node(Path.of(filename));
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
		var isConflictResolvedEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof ConflictResolvedEvent;
		verify(eventConsumer).accept(ArgumentMatchers.argThat(isConflictResolvedEvent));
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
		var isConflictResolvedEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof ConflictResolvedEvent;
		verify(eventConsumer).accept(ArgumentMatchers.argThat(isConflictResolvedEvent));
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
		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), DIR_ID);
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
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
	public void testResolveConflictingDirTriviallyDespiteTrailingBytes(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), DIR_ID + "\n"); // trailing bytes beyond MAX_DIR_ID_LENGTH
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertEquals("foo.c9r", resolved.fullCiphertextFileName);
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	@Test
	public void testResolveConflictingDirWithDifferentDirId(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), OTHER_DIR_ID);
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertEquals("baz.c9r", resolved.fullCiphertextFileName);
		Assertions.assertEquals("bar (1)", resolved.cleartextName);
		Assertions.assertFalse(Files.exists(unresolved.ciphertextPath));
		// each of the two dirs must keep referencing its own dir id:
		Assertions.assertEquals(OTHER_DIR_ID, Files.readString(dir.resolve("baz.c9r/dir.c9r")));
		Assertions.assertEquals(DIR_ID, Files.readString(dir.resolve("foo.c9r/dir.c9r")));
	}

	@Test
	public void testPostponeConflictResolutionForIncompleteConflictingDir(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r")); // dir.c9r not copied (yet)
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);

		Assertions.assertTrue(result.findAny().isEmpty());
		Assertions.assertTrue(Files.exists(dir.resolve("foo (1).c9r")));
		Assertions.assertTrue(Files.exists(dir.resolve("foo.c9r")));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	@Test
	public void testPostponeConflictResolutionForEmptyDirFile(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.createFile(dir.resolve("foo (1).c9r/dir.c9r")); // dir id not written (yet)
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);

		Assertions.assertTrue(result.findAny().isEmpty());
		Assertions.assertTrue(Files.exists(dir.resolve("foo (1).c9r/dir.c9r")));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	@Test
	public void testPostponeConflictResolutionForTruncatedDirFile(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), DIR_ID.substring(0, 20)); // dir id not written completely (yet)
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);

		Assertions.assertTrue(result.findAny().isEmpty());
		Assertions.assertTrue(Files.exists(dir.resolve("foo (1).c9r")));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	@Test
	public void testPostponeConflictResolutionForIncompleteCanonicalDir(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r")); // dir.c9r not written (yet)
		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);

		Assertions.assertTrue(result.findAny().isEmpty());
		Assertions.assertEquals(DIR_ID, Files.readString(dir.resolve("foo (1).c9r/dir.c9r")));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	/**
	 * Regression test for <a href="https://github.com/cryptomator/cryptofs/issues/355">#355</a>: A third party
	 * application copied ciphertext directories, appending a suffix to their names. Since such a copy is not atomic,
	 * the conflict resolver used to rename directories whose <code>dir.c9r</code> had not been copied yet, leaving two
	 * directory entries referencing the same dir id ("Directory ID reused"). Postponing must therefore not be a dead
	 * end: once the copy is complete, the duplicate is recognized and removed.
	 */
	@Test
	public void testPostponedConflictIsResolvedOnceDirFileExists(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r")); // dir.c9r not copied (yet)
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Assertions.assertTrue(conflictResolver.process(unresolved).findAny().isEmpty());

		Files.writeString(dir.resolve("foo (1).c9r/dir.c9r"), DIR_ID); // copy completed in the meantime
		Node resolved = conflictResolver.process(unresolved).findAny().get();

		Assertions.assertEquals("foo.c9r", resolved.fullCiphertextFileName);
		Assertions.assertFalse(Files.exists(dir.resolve("foo (1).c9r")), "no second entry referencing " + DIR_ID);
		Assertions.assertEquals(DIR_ID, Files.readString(dir.resolve("foo.c9r/dir.c9r")));
		Mockito.verifyNoInteractions(fileNameCryptor);
	}

	@Test
	public void testResolveConflictingSymlinkAndDirByChoosingNewName(@TempDir Path dir) throws IOException {
		Files.createDirectory(dir.resolve("foo (1).c9r"));
		Files.createDirectory(dir.resolve("foo.c9r"));
		Files.writeString(dir.resolve("foo (1).c9r/symlink.c9r"), "linktarget");
		Files.writeString(dir.resolve("foo.c9r/dir.c9r"), DIR_ID);
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar";
		unresolved.extractedCiphertext = "foo";

		Stream<Node> result = conflictResolver.process(unresolved);
		Node resolved = result.findAny().get();

		Assertions.assertEquals("baz.c9r", resolved.fullCiphertextFileName);
		Assertions.assertTrue(Files.exists(dir.resolve("baz.c9r/symlink.c9r")));
		Assertions.assertTrue(Files.exists(dir.resolve("foo.c9r/dir.c9r")));
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

	@Test
	public void testConflictResolutionFails(@TempDir Path dir) throws IOException {
		var p1 = Files.createFile(dir.resolve("foo (1).c9r"));
		var p2 = Files.createFile(dir.resolve("foo.c9r"));
		Mockito.when(fileNameCryptor.encryptFilename(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn("baz");
		Node unresolved = new Node(dir.resolve("foo (1).c9r"));
		unresolved.cleartextName = "bar.txt";
		unresolved.extractedCiphertext = "foo";

		var conflictResolverSpy = Mockito.spy(conflictResolver);
		Mockito.doThrow(IOException.class).when(conflictResolverSpy).resolveConflict(Mockito.any(), Mockito.any());

		Stream<Node> result = Assertions.assertDoesNotThrow(() -> conflictResolverSpy.process(unresolved));
		Assertions.assertEquals(0, result.toList().size());
		Assertions.assertTrue(Files.exists(p1));
		Assertions.assertTrue(Files.exists(p2));
		var isConflictResolutionFailedEvent = (ArgumentMatcher<FilesystemEvent>) ev -> ev instanceof ConflictResolutionFailedEvent;
		verify(eventConsumer).accept(ArgumentMatchers.argThat(isConflictResolutionFailedEvent));
	}

}