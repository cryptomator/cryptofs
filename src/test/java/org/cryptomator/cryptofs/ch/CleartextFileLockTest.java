package org.cryptomator.cryptofs.ch;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

public class CleartextFileLockTest {

	private FileChannel channel;
	private long size = 3728l;
	private long position = 323l;
	private FileLock delegate;
	private CleartextFileLock inTest;

	@BeforeEach
	public void setup() {
		channel = Mockito.mock(FileChannel.class);
		delegate = Mockito.mock(FileLock.class);
		Mockito.when(channel.isOpen()).thenReturn(true);
	}

	@Nested
	@DisplayName("Shared Locks")
	public class SharedLockTests {

		@BeforeEach
		public void setup() {
			Mockito.when(delegate.isValid()).thenReturn(true);
			Mockito.when(delegate.isShared()).thenReturn(true);
			inTest = new CleartextFileLock(channel, delegate, position, size);
		}

		@Test
		@DisplayName("delegate() is delegate")
		public void testDelegate() {
			Assertions.assertSame(delegate, inTest.delegate());
		}

		@Test
		@DisplayName("position() is 323")
		public void testPosition() {
			Assertions.assertEquals(position, inTest.position());
		}

		@Test
		@DisplayName("size() is 3728")
		public void testSize() {
			Assertions.assertEquals(size, inTest.size());
		}

		@Test
		@DisplayName("channel() is channel")
		public void testChannel() {
			Assertions.assertSame(channel, inTest.channel());
		}

		@Test
		@DisplayName("isShared() is true")
		public void testShared() {
			Assertions.assertTrue(inTest.isShared());
		}

		@Test
		@DisplayName("isValid() is true")
		public void testIsValid() {
			Assertions.assertTrue(inTest.isValid());
		}

		@Nested
		@DisplayName("After releasing the lock")
		public class ReleasedLock {

			@BeforeEach
			public void setup() throws IOException {
				inTest.release();
				Mockito.when(delegate.isValid()).thenReturn(false);
			}

			@Test
			@DisplayName("isValid() is false")
			public void testIsValid() {
				Assertions.assertFalse(inTest.isValid());
			}

			@Test
			@DisplayName("release() is called on the delegate")
			public void testReleaseDelegate() throws IOException {
				Mockito.verify(delegate).release();
			}

		}

		@Nested
		@DisplayName("After closing the channel")
		public class ClosedChannel {

			@BeforeEach
			public void setup() throws IOException {
				Mockito.when(channel.isOpen()).thenReturn(false);
			}

			@Test
			@DisplayName("isValid() is false")
			public void testIsValid() {
				Assertions.assertFalse(inTest.isValid());
			}

		}

	}

	@Nested
	@DisplayName("Exclusive Locks")
	public class ExclusiveLockTests {

		@BeforeEach
		public void setup() {
			Mockito.when(delegate.isValid()).thenReturn(true);
			Mockito.when(delegate.isShared()).thenReturn(false);
			inTest = new CleartextFileLock(channel, delegate, position, size);
		}

		@Test
		@DisplayName("delegate() is delegate")
		public void testDelegate() {
			Assertions.assertSame(delegate, inTest.delegate());
		}

		@Test
		@DisplayName("position() is 323")
		public void testPosition() {
			Assertions.assertEquals(position, inTest.position());
		}

		@Test
		@DisplayName("size() is 3728")
		public void testSize() {
			Assertions.assertEquals(size, inTest.size());
		}

		@Test
		@DisplayName("channel() is channel")
		public void testChannel() {
			Assertions.assertSame(channel, inTest.channel());
		}

		@Test
		@DisplayName("isShared() is false")
		public void testShared() {
			Assertions.assertFalse(inTest.isShared());
		}

		@Test
		@DisplayName("isValid() is true")
		public void testIsValid() {
			Assertions.assertTrue(inTest.isValid());
		}

		@Nested
		@DisplayName("After releasing the lock")
		public class ReleasedLock {

			@BeforeEach
			public void setup() throws IOException {
				inTest.release();
				Mockito.when(delegate.isValid()).thenReturn(false);
			}

			@Test
			@DisplayName("isValid() is false")
			public void testIsValid() {
				Assertions.assertFalse(inTest.isValid());
			}

			@Test
			@DisplayName("release() is called on the delegate")
			public void testReleaseDelegate() throws IOException {
				Mockito.verify(delegate).release();
			}

		}

		@Nested
		@DisplayName("After closing the channel")
		public class ClosedChannel {

			@BeforeEach
			public void setup() throws IOException {
				Mockito.when(channel.isOpen()).thenReturn(false);
			}

			@Test
			@DisplayName("isValid() is false")
			public void testIsValid() {
				Assertions.assertFalse(inTest.isValid());
			}

		}

	}

}
