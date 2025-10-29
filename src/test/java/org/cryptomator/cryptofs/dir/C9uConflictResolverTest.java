package org.cryptomator.cryptofs.dir;

import org.cryptomator.cryptofs.common.Constants;
import org.cryptomator.cryptofs.inuse.InUseManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.mockito.Mockito.mock;

public class C9uConflictResolverTest {

	C9uConflictResolver c9uConflictResolver;

	@BeforeEach
	void beforeEach() {
		c9uConflictResolver = new C9uConflictResolver();
	}

	@Test
	@DisplayName("If filename is valid base64, the file exists")
	void validBase64KeepsExisting(@TempDir Path tmpDir) throws IOException {
		var ciphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFFggggHH=="+ Constants.INUSE_FILE_SUFFIX);
		Files.createFile(ciphertextPath);
		var node = new Node(ciphertextPath);

		var result = c9uConflictResolver.process(node);

		Assertions.assertEquals(0, result.count());
		Assertions.assertTrue(Files.exists(ciphertextPath));
	}

	@Test
	@DisplayName("If filename is NOT valid base64, the file is deleted")
	void InvalidBase64Deleted(@TempDir Path tmpDir) throws IOException {
		var ciphertextPath = tmpDir.resolve("aaaaBBBBccccDDDDeeeeFFFFggggHH== (conflicted copy)"+ Constants.INUSE_FILE_SUFFIX);
		Files.createFile(ciphertextPath);
		var node = new Node(ciphertextPath);

		var result = c9uConflictResolver.process(node);

		Assertions.assertEquals(0, result.count());
		Assertions.assertTrue(Files.notExists(ciphertextPath));
	}
}
