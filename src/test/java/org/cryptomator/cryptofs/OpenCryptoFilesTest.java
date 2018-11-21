package org.cryptomator.cryptofs;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.mockito.Mockito.mock;

public class OpenCryptoFilesTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private CryptoFileSystemComponent cryptoFileSystemComponent = mock(CryptoFileSystemComponent.class);
	private FinallyUtil finallyUtil = mock(FinallyUtil.class);

	private OpenCryptoFiles inTest;

	@Before
	public void setup() {
		Mockito.when(cryptoFileSystemComponent.newOpenCryptoFileComponent(Mockito.any())).thenAnswer(invocation -> {
			OpenCryptoFileComponent subComponent = mock(OpenCryptoFileComponent.class);
			OpenCryptoFile file = mock(OpenCryptoFile.class);
			Mockito.when(subComponent.openCryptoFile()).thenReturn(file);
			return subComponent;
		});

		inTest = new OpenCryptoFiles(cryptoFileSystemComponent, finallyUtil);
	}

	@Test
	public void testGetOrCreate() throws IOException {
		EffectiveOpenOptions openOptions = mock(EffectiveOpenOptions.class);
		Path p1 = Paths.get("/foo");
		Path p2 = Paths.get("/bar");

		Assert.assertSame(inTest.getOrCreate(p1, openOptions), inTest.getOrCreate(p1, openOptions));
		Assert.assertNotSame(inTest.getOrCreate(p1, openOptions), inTest.getOrCreate(p2, openOptions));
	}

	@Test
	public void testTwoPhaseMoveFailsWhenTargetIsOpened() throws IOException {
		EffectiveOpenOptions openOptions = mock(EffectiveOpenOptions.class);
		Path src = Paths.get("/src").toAbsolutePath();
		Path dst = Paths.get("/dst").toAbsolutePath();
		inTest.getOrCreate(dst, openOptions);

		thrown.expect(FileAlreadyExistsException.class);
		inTest.prepareMove(src, dst);
	}

	@Test
	public void testTwoPhaseMoveDoesntChangeAnythingWhenRolledBack() throws IOException {
		EffectiveOpenOptions openOptions = mock(EffectiveOpenOptions.class);
		Path src = Paths.get("/src");
		Path dst = Paths.get("/dst");
		inTest.getOrCreate(src, openOptions);

		Assert.assertTrue(inTest.get(src).isPresent());
		Assert.assertFalse(inTest.get(dst).isPresent());
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst)) {
			twoPhaseMove.rollback();
		}
		Assert.assertTrue(inTest.get(src).isPresent());
		Assert.assertFalse(inTest.get(dst).isPresent());
	}

	@Test
	public void testTwoPhaseMoveChangesReferencesWhenCommitted() throws IOException {
		EffectiveOpenOptions openOptions = mock(EffectiveOpenOptions.class);
		Path src = Paths.get("/src").toAbsolutePath();
		Path dst = Paths.get("/dst").toAbsolutePath();
		inTest.getOrCreate(src, openOptions);

		Assert.assertTrue(inTest.get(src).isPresent());
		Assert.assertFalse(inTest.get(dst).isPresent());
		OpenCryptoFile srcFile = inTest.get(src).get();
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst)) {
			twoPhaseMove.commit();
		}
		Assert.assertFalse(inTest.get(src).isPresent());
		Assert.assertTrue(inTest.get(dst).isPresent());
		OpenCryptoFile dstFile = inTest.get(dst).get();
		Assert.assertSame(srcFile, dstFile);
	}

}
