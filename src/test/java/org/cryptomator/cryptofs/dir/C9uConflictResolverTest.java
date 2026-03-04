package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

public class C9uConflictResolverTest {

	InUseManager inUseManager;
	C9uConflictResolver c9uConflictResolver;

	@BeforeEach
	void beforeEach() {
		inUseManager = Mockito.mock(InUseManager.class);
		c9uConflictResolver = new C9uConflictResolver(inUseManager);
	}

	@Test
	@DisplayName("If filename is valid base64, don't touch the file")
	void validBase64KeepsExisting(@TempDir Path tmpDir) throws IOException {
		var ciphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFFggggHH==" + Constants.INUSE_FILE_SUFFIX);
		Files.createFile(ciphertextPath);
		var node = new Node(ciphertextPath);

		var result = c9uConflictResolver.process(node);

		Assertions.assertEquals(0, result.count());
		Assertions.assertTrue(Files.exists(ciphertextPath));
	}

	@Test
	@DisplayName("If filename contains partially valid base64, the file is deleted and inUse status checked")
	void PartiallyBase64Deleted(@TempDir Path tmpDir) throws IOException {
		var ciphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFFggggHH== (conflicted copy)" + Constants.INUSE_FILE_SUFFIX);
		var dataCiphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFFggggHH==" + Constants.CRYPTOMATOR_FILE_SUFFIX);
		Files.createFile(ciphertextPath);
		var node = new Node(ciphertextPath);

		var result = c9uConflictResolver.process(node);

		Assertions.assertEquals(0, result.count());
		Assertions.assertTrue(Files.notExists(ciphertextPath));
		verify(inUseManager).checkUseStatus(dataCiphertextPath);
	}

	@Test
	@DisplayName("If filename is mumbojumbo, the file is just deleted")
	void NoBase64Deleted(@TempDir Path tmpDir) throws IOException {
		var ciphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFF (conflicted copy)" + Constants.INUSE_FILE_SUFFIX);
		Files.createFile(ciphertextPath);
		var node = new Node(ciphertextPath);

		var result = c9uConflictResolver.process(node);

		Assertions.assertEquals(0, result.count());
		Assertions.assertTrue(Files.notExists(ciphertextPath));
		verify(inUseManager).checkUseStatus(any());
	}
}
