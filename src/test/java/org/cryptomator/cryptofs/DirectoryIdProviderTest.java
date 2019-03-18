package org.cryptomator.cryptofs;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.verification.VerificationMode;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

public class DirectoryIdProviderTest {

	private DirectoryIdLoader loader = mock(DirectoryIdLoader.class);

	private Path aPath = mock(Path.class);
	private Path anotherPath = mock(Path.class);

	private String aDirectoryId = "foo32";
	private String anotherDirectoryId = "foo42";

	private DirectoryIdProvider inTest = new DirectoryIdProvider(loader);

	@Test
	public void testLoadInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
	}

	@Test
	public void testIOExceptionFromLoaderIsWrappedAndRethrown() throws IOException {
		IOException originalIoException = new IOException();
		when(loader.load(aPath)).thenThrow(originalIoException);

		IOException e = Assertions.assertThrows(IOException.class, () -> {
			inTest.load(aPath);
		});
		Assertions.assertTrue(e.getCause() instanceof ExecutionException);
		Assertions.assertEquals(originalIoException, e.getCause().getCause());
	}

	@Test
	public void testSecondLoadDoesNotInvokeLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
		verify(loader).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testSecondLoadAfterRemoveInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.delete(aPath);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
		verify(loader, times(2)).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testMoveOnNonExistingEntryDoesNothing() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);
		when(loader.load(anotherPath)).thenReturn(anotherDirectoryId);

		inTest.move(aPath, anotherPath);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
		Assertions.assertSame(anotherDirectoryId, inTest.load(anotherPath));
		verify(loader).load(aPath);
		verify(loader).load(anotherPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testLoadOnOtherPathAfterMoveDoesNotInvokeLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.move(aPath, anotherPath);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
		verify(loader, Mockito.atLeastOnce()).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testLoadOnPathAfterMoveInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.move(aPath, anotherPath);

		Assertions.assertSame(aDirectoryId, inTest.load(aPath));
		verify(loader, times(2)).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	private Matcher<? extends Throwable> hasCauseThat(Matcher<? extends Throwable> check) {
		return new TypeSafeMatcher<Throwable>(Throwable.class) {
			@Override
			public void describeTo(Description description) {
				description.appendText("a throwable with cause that ").appendDescriptionOf(check);
			}

			@Override
			protected boolean matchesSafely(Throwable item) {
				return check.matches(item.getCause());
			}
		};
	}

}
