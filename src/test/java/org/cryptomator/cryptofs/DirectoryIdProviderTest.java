package org.cryptomator.cryptofs;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static org.mockito.internal.verification.VerificationModeFactory.times;

import java.io.IOException;
import java.nio.file.Path;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

public class DirectoryIdProviderTest {

	@Rule
	public MockitoRule mockitoRule = MockitoJUnit.rule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private DirectoryIdLoader loader = mock(DirectoryIdLoader.class);

	private Path aPath = mock(Path.class);
	private Path anotherPath = mock(Path.class);

	private String aDirectoryId = "foo32";
	private String anotherDirectoryId = "foo42";

	private DirectoryIdProvider inTest = new DirectoryIdProvider(loader);

	@Test
	public void testLoadInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		assertThat(inTest.load(aPath), is(aDirectoryId));
	}

	@Test
	public void testIOExceptionFromLoaderIsWrappedAndRethrown() throws IOException {
		IOException originalIoException = new IOException();
		when(loader.load(aPath)).thenThrow(originalIoException);

		thrown.expect(IOException.class);
		thrown.expectCause(hasCauseThat(is(originalIoException)));

		inTest.load(aPath);
	}

	@Test
	public void testSecondLoadDoesNotInvokeLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);

		assertThat(inTest.load(aPath), is(aDirectoryId));
		verify(loader).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testSecondLoadAfterRemoveInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.delete(aPath);

		assertThat(inTest.load(aPath), is(aDirectoryId));
		verify(loader, times(2)).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testMoveOnNonExistingEntryDoesNothing() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);
		when(loader.load(anotherPath)).thenReturn(anotherDirectoryId);

		inTest.move(aPath, anotherPath);

		assertThat(inTest.load(aPath), is(aDirectoryId));
		assertThat(inTest.load(anotherPath), is(anotherDirectoryId));
		verify(loader).load(aPath);
		verify(loader).load(anotherPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testLoadOnOtherPathAfterMoveDoesNotInvokeLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.move(aPath, anotherPath);

		assertThat(inTest.load(anotherPath), is(aDirectoryId));
		verify(loader).load(aPath);
		verifyNoMoreInteractions(loader);
	}

	@Test
	public void testLoadOnPathAfterMoveInvokesLoader() throws IOException {
		when(loader.load(aPath)).thenReturn(aDirectoryId);

		inTest.load(aPath);
		inTest.move(aPath, anotherPath);

		assertThat(inTest.load(aPath), is(aDirectoryId));
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
