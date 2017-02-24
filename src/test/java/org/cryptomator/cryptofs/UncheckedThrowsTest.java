package org.cryptomator.cryptofs;

import static org.cryptomator.cryptofs.UncheckedThrows.allowUncheckedThrowsOf;
import static org.cryptomator.cryptofs.UncheckedThrows.rethrowUnchecked;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.IOException;

import org.cryptomator.cryptolib.api.CryptoException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class UncheckedThrowsTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testUncheckedThrows() throws IOException {
		IOException exception = new IOException();

		thrown.expect(is(exception));

		allowUncheckedThrowsOf(IOException.class).from(() -> {
			rethrowUnchecked(IOException.class).from(() -> {
				throw exception;
			});
		});
	}

	@Test
	public void testUncheckedExceptionIsUnaffectedByUncheckedThrows() throws IOException {
		RuntimeException exception = new RuntimeException();

		thrown.expect(is(exception));

		allowUncheckedThrowsOf(IOException.class).from(() -> {
			rethrowUnchecked(IOException.class).from(() -> {
				throw exception;
			});
		});
	}

	@Test
	public void testNestedUncheckedThrows() throws IOException {
		IOException exception = new IOException();

		thrown.expect(is(exception));

		allowUncheckedThrowsOf(IOException.class).from(() -> {
			allowUncheckedThrowsOf(CryptoException.class).from(() -> {
				rethrowUnchecked(IOException.class).from(() -> {
					throw exception;
				});
			});
		});
	}

	@Test
	public void testUncheckedThrowsWhenNotAllowed() throws IOException {
		thrown.expect(IllegalStateException.class);
		thrown.expectMessage("Unchecked throws of java.lang.Exception not allowed");

		rethrowUnchecked(Exception.class);
	}

	@Test
	public void testUncheckedThrowsWhenOtherTypeAllowed() throws IOException {
		thrown.expect(IllegalStateException.class);
		thrown.expectMessage("Unchecked throws of java.lang.Exception not allowed");

		allowUncheckedThrowsOf(IOException.class).from(() -> {
			rethrowUnchecked(Exception.class);
		});
	}

	@Test
	public void testResultFromSupplier() throws IOException {
		Object expectedResult = new Object();

		Object result = allowUncheckedThrowsOf(IOException.class).from(() -> {
			return rethrowUnchecked(IOException.class).from(() -> {
				return expectedResult;
			});
		});

		assertThat(result, is(expectedResult));
	}

	@Test
	public void testExecuteRunnable() throws IOException {
		@SuppressWarnings("unchecked")
		RunnableThrowingException<IOException> runnable = mock(RunnableThrowingException.class);

		allowUncheckedThrowsOf(IOException.class).from(() -> {
			rethrowUnchecked(IOException.class).from(runnable);
		});

		verify(runnable).run();
	}

}
