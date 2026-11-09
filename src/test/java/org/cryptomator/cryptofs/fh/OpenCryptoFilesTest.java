package org.cryptomator.cryptofs.fh;

import org.awaitility.Awaitility;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.EffectiveOpenOptions;
import org.cryptomator.cryptofs.event.DecryptionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.mockito.Mockito.mock;

public class OpenCryptoFilesTest {

	private final OpenCryptoFileComponent.Factory openCryptoFileComponentFactory = mock(OpenCryptoFileComponent.Factory.class);
	private final OpenCryptoFile file = mock(OpenCryptoFile.class, "file");
	private final FileChannel ciphertextFileChannel = Mockito.mock(FileChannel.class);
	private final Consumer<FilesystemEvent> eventConsumer = mock(Consumer.class);

	private OpenCryptoFiles inTest;

	@BeforeEach
	public void setup() throws IOException, ReflectiveOperationException {
		OpenCryptoFileComponent subComponent = mock(OpenCryptoFileComponent.class);
		Mockito.when(subComponent.openCryptoFile()).thenReturn(file);

		Mockito.when(openCryptoFileComponentFactory.create(Mockito.any(), Mockito.any())).thenReturn(subComponent);
		Mockito.when(file.newFileChannel(Mockito.any())).thenReturn(ciphertextFileChannel);

		inTest = new OpenCryptoFiles(openCryptoFileComponentFactory, eventConsumer);
	}

	@Test
	public void testGetOrCreate() {
		OpenCryptoFileComponent subComponent1 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file1 = mock(OpenCryptoFile.class);
		Mockito.when(subComponent1.openCryptoFile()).thenReturn(file1);

		OpenCryptoFileComponent subComponent2 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file2 = mock(OpenCryptoFile.class);
		Mockito.when(subComponent2.openCryptoFile()).thenReturn(file2);

		Mockito.when(openCryptoFileComponentFactory.create(Mockito.any(), Mockito.any())).thenReturn(subComponent1, subComponent2);

		Path p1 = Path.of("/foo");
		Path p2 = Path.of("/bar");

		Assertions.assertSame(file1, inTest.getOrCreate(p1));
		Assertions.assertSame(file1, inTest.getOrCreate(p1));
		Assertions.assertSame(file2, inTest.getOrCreate(p2));
		Assertions.assertNotSame(file1, file2);
	}

	@Test
	public void testWriteCiphertextFile() throws IOException {
		Path path = Path.of("/foo");
		EffectiveOpenOptions openOptions = Mockito.mock(EffectiveOpenOptions.class);
		ByteBuffer contents = StandardCharsets.UTF_8.encode("hello world");

		inTest.writeCiphertextFile(Mockito.mock(CryptoPath.class), path, openOptions, contents);

		Mockito.verify(ciphertextFileChannel).write(contents);
	}

	@Test
	public void testReadCiphertextFile() throws IOException {
		byte[] contents = "hello world".getBytes(StandardCharsets.UTF_8);
		Path path = Path.of("/foo");
		EffectiveOpenOptions openOptions = Mockito.mock(EffectiveOpenOptions.class);
		Mockito.when(ciphertextFileChannel.size()).thenReturn((long) contents.length);
		Mockito.when(ciphertextFileChannel.read(Mockito.any(ByteBuffer.class))).thenAnswer(invocation -> {
			ByteBuffer buf = invocation.getArgument(0);
			buf.put(contents);
			return contents.length;
		});

		ByteBuffer bytesRead = inTest.readCiphertextFile(Mockito.mock(CryptoPath.class), path, openOptions, 1337);

		Assertions.assertEquals("hello world", StandardCharsets.UTF_8.decode(bytesRead).toString());
	}

	@Test
	public void testTwoPhaseMoveFailsWhenTargetIsOpened() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		inTest.getOrCreate(dst);

		Assertions.assertThrows(FileAlreadyExistsException.class, () -> {
			inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), false);
		});
	}

	@Test
	public void testTwoPhaseMoveDoesntChangeAnythingWhenRolledBack() throws IOException {
		Path src = Path.of("/src");
		Path dst = Path.of("/dst");
		inTest.getOrCreate(src);

		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), false)) {
			twoPhaseMove.rollback();
		}
		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
	}

	@Test
	public void testTwoPhaseMoveChangesReferencesWhenCommitted() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		inTest.getOrCreate(src);

		Assertions.assertTrue(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		OpenCryptoFile srcFile = inTest.get(src).get();
		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), false)) {
			twoPhaseMove.commit();
		}
		Assertions.assertFalse(inTest.get(src).isPresent());
		Assertions.assertTrue(inTest.get(dst).isPresent());
		OpenCryptoFile dstFile = inTest.get(dst).get();
		Assertions.assertSame(srcFile, dstFile);
	}

	@Test
	public void testTwoPhaseMoveUpdatesCleartextPathWhenCommitted() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		CryptoPath cleartextDst = mock(CryptoPath.class);
		OpenCryptoFile srcFile = inTest.getOrCreate(src);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, cleartextDst, false)) {
			twoPhaseMove.commit();
		}

		Mockito.verify(srcFile).updateCurrentCleartextPath(cleartextDst);
	}

	@Test
	public void testTwoPhaseMoveReplacingOpenedTargetDetachesTargetWhenCommitted() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		OpenCryptoFile srcFile = mockOpenCryptoFile(src);
		OpenCryptoFile dstFile = mockOpenCryptoFile(dst);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true)) {
			Assertions.assertSame(dstFile, inTest.get(dst).get());
			twoPhaseMove.commit();
		}

		Assertions.assertFalse(inTest.get(src).isPresent());
		Assertions.assertSame(srcFile, inTest.get(dst).get());
		var inOrder = Mockito.inOrder(dstFile, srcFile);
		inOrder.verify(dstFile).updateCurrentFilePath(null);
		inOrder.verify(srcFile).updateCurrentFilePath(dst);
	}

	@ParameterizedTest
	@ValueSource(strings = {"/dst", "/foo/../dst"})
	public void testTwoPhaseMoveReplacingOpenedTargetWithUnopenedSourceUnregistersTargetWhenCommitted(String movedTo) throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		OpenCryptoFile dstFile = mockOpenCryptoFile(dst);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, Path.of(movedTo).toAbsolutePath(), Mockito.mock(CryptoPath.class), true)) {
			twoPhaseMove.commit();
		}

		Assertions.assertFalse(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		Mockito.verify(dstFile).updateCurrentFilePath(null);
	}

	@Test
	public void testTwoPhaseMoveReplacingOpenedTargetDoesntChangeAnythingWhenRolledBack() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		OpenCryptoFile srcFile = mockOpenCryptoFile(src);
		OpenCryptoFile dstFile = mockOpenCryptoFile(dst);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true)) {
			twoPhaseMove.rollback();
		}

		Assertions.assertSame(srcFile, inTest.get(src).get());
		Assertions.assertSame(dstFile, inTest.get(dst).get());
		Mockito.verify(srcFile, Mockito.never()).updateCurrentFilePath(Mockito.any());
		Mockito.verify(dstFile, Mockito.never()).updateCurrentFilePath(Mockito.any());
	}

	@Test
	public void testTwoPhaseMoveDetachesReplacedPathsWhenCommitted() throws IOException {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		Path replaced = Path.of("/replaced").toAbsolutePath();
		OpenCryptoFile replacedFile = mockOpenCryptoFile(replaced);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true, replaced)) {
			twoPhaseMove.commit();
		}

		Assertions.assertFalse(inTest.get(replaced).isPresent());
		Mockito.verify(replacedFile).updateCurrentFilePath(null);
	}

	@Test
	public void testTwoPhaseMoveDoesntMoveFileClosedDuringCommit() throws Exception {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		OpenCryptoFile srcFile = mockOpenCryptoFile(src);
		var closeListener = ArgumentCaptor.forClass(FileCloseListener.class);
		Mockito.verify(openCryptoFileComponentFactory).create(Mockito.eq(src), closeListener.capture());

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true)) {
			FutureTask<?> committed = new FutureTask<>(twoPhaseMove::commit, null);
			synchronized (srcFile) { // unregister under the monitor, as the last channel closing does
				startAndAwait(new Thread(committed), committed, Thread.State.BLOCKED);
				closeListener.getValue().close(src, srcFile);
			}
			committed.get(5, TimeUnit.SECONDS);
		}

		Assertions.assertFalse(inTest.get(src).isPresent());
		Assertions.assertFalse(inTest.get(dst).isPresent());
		Mockito.verify(srcFile, Mockito.never()).updateCurrentFilePath(Mockito.any());
	}

	@Test
	public void testReplaceDetachesOpenedFileAfterOperation() throws IOException {
		Path path = Path.of("/foo").toAbsolutePath();
		OpenCryptoFile openFile = mockOpenCryptoFile(path);

		inTest.replace(path, () -> Mockito.verify(openFile, Mockito.never()).updateCurrentFilePath(Mockito.any()));

		Assertions.assertFalse(inTest.get(path).isPresent());
		Mockito.verify(openFile).updateCurrentFilePath(null);
	}

	@Test
	public void testReplaceKeepsOpenedFileAndReleasesLockWhenOperationFails() throws Exception {
		Path path = Path.of("/foo").toAbsolutePath();
		OpenCryptoFile openFile = mockOpenCryptoFile(path);

		Assertions.assertThrows(IOException.class, () -> inTest.replace(path, () -> {
			throw new IOException("ERROR");
		}));

		Assertions.assertSame(openFile, inTest.get(path).get());
		Mockito.verify(openFile, Mockito.never()).updateCurrentFilePath(Mockito.any());
		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> inTest.open(path, () -> null));
	}

	@Test
	public void testNewFileChannelFailsOutsideOpenOperation() {
		Path path = Path.of("/foo").toAbsolutePath();

		Assertions.assertThrows(IllegalStateException.class, () -> inTest.newFileChannel(Mockito.mock(CryptoPath.class), path, Mockito.mock(EffectiveOpenOptions.class)));
	}

	@Test
	public void testOpenDeliversHeaderDecryptionEventAfterReleasingLock() throws IOException {
		Path path = Path.of("/foo").toAbsolutePath();
		HeaderDecryptionException headerDecryptionException = new HeaderDecryptionException(path, new IllegalArgumentException());
		DecryptionFailedEvent event = headerDecryptionException.getEvent();
		Mockito.when(file.newFileChannel(Mockito.any())).thenThrow(headerDecryptionException);
		Mockito.doAnswer(invocation -> {
			inTest.prepareMove(path, Path.of("/bar").toAbsolutePath(), Mockito.mock(CryptoPath.class), true).close(); // waits forever if the lock was still held
			return null;
		}).when(eventConsumer).accept(event);

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
			Assertions.assertThrows(HeaderDecryptionException.class, () -> openChannel(path));
		});
		Mockito.verify(eventConsumer).accept(event);
	}

	@ParameterizedTest
	@ValueSource(booleans = {true, false})
	public void testReadOrWriteCiphertextFileAccessesContentsAfterReleasingLock(boolean write) throws IOException {
		Path path = Path.of("/foo").toAbsolutePath();
		Answer<Integer> movingAnswer = invocation -> {
			inTest.prepareMove(path, Path.of("/bar").toAbsolutePath(), Mockito.mock(CryptoPath.class), true).close(); // waits forever if the lock was still held
			return 0;
		};
		Mockito.when(ciphertextFileChannel.read(Mockito.any(ByteBuffer.class))).thenAnswer(movingAnswer);
		Mockito.when(ciphertextFileChannel.write(Mockito.any(ByteBuffer.class))).thenAnswer(movingAnswer);

		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
			if (write) {
				inTest.writeCiphertextFile(Mockito.mock(CryptoPath.class), path, Mockito.mock(EffectiveOpenOptions.class), ByteBuffer.allocate(0));
			} else {
				inTest.readCiphertextFile(Mockito.mock(CryptoPath.class), path, Mockito.mock(EffectiveOpenOptions.class), 1337);
			}
		});
		Mockito.verify(ciphertextFileChannel, write ? Mockito.never() : Mockito.times(1)).read(Mockito.any(ByteBuffer.class));
		Mockito.verify(ciphertextFileChannel, write ? Mockito.times(1) : Mockito.never()).write(Mockito.any(ByteBuffer.class));
	}

	@ParameterizedTest
	@ValueSource(strings = {"/src", "/dst", "/replaced"})
	public void testOpenWaitsForTwoPhaseMove(String openedPath) throws Exception {
		Path path = Path.of(openedPath).toAbsolutePath();

		assertOpenWaitsForTwoPhaseMove(() -> openChannel(path));
	}

	private void assertOpenWaitsForTwoPhaseMove(Callable<?> opening) throws Exception {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		Path replaced = Path.of("/replaced").toAbsolutePath();
		FutureTask<?> opened = new FutureTask<>(opening);
		Thread opener = new Thread(opened);

		try (OpenCryptoFiles.TwoPhaseMove twoPhaseMove = inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true, replaced)) {
			startAndAwait(opener, opened, Thread.State.WAITING);
			twoPhaseMove.commit();
		}

		opened.get(5, TimeUnit.SECONDS);
	}

	@Test
	public void testOpenWaitsForReplace() throws Exception {
		Path path = Path.of("/foo").toAbsolutePath();
		FutureTask<?> opened = new FutureTask<>(() -> openChannel(path));
		Thread opener = new Thread(opened);

		inTest.replace(path, () -> startAndAwait(opener, opened, Thread.State.WAITING));

		opened.get(5, TimeUnit.SECONDS);
		Assertions.assertSame(file, inTest.get(path).get());
		Mockito.verify(file, Mockito.never()).updateCurrentFilePath(Mockito.any());
	}

	@Test
	public void testOpenOfOtherPathDoesntWaitForReplace() throws IOException {
		Path path = Path.of("/foo").toAbsolutePath();
		Path otherPath = Path.of("/bar").toAbsolutePath();

		inTest.replace(path, () -> Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> openChannel(otherPath)));
	}

	@Test
	public void testPathLocksAreDiscardedWhenUnused() throws Exception {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();

		openChannel(src);
		inTest.replace(dst, () -> {});
		inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true).close();

		var pathLocksField = OpenCryptoFiles.class.getDeclaredField("pathLocks");
		pathLocksField.setAccessible(true);
		Assertions.assertTrue(((Map<?, ?>) pathLocksField.get(inTest)).isEmpty());
	}

	private void startAndAwait(Thread thread, Future<?> result, Thread.State state) {
		thread.start();
		Awaitility.await().atMost(5, TimeUnit.SECONDS).until(() -> thread.getState() == state);
		Assertions.assertFalse(result.isDone());
	}

	@Test
	public void testTwoPhaseMoveWaitsForOpen() throws Exception {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		CountDownLatch opening = new CountDownLatch(1);
		CountDownLatch finishOpening = new CountDownLatch(1);
		FutureTask<Object> opened = new FutureTask<>(() -> inTest.open(dst, () -> {
			opening.countDown();
			try {
				return finishOpening.await(5, TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new InterruptedIOException();
			}
		}));
		FutureTask<Object> moved = new FutureTask<>(() -> {
			inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), true).close();
			return null;
		});
		Thread mover = new Thread(moved);

		new Thread(opened).start();
		opening.await(5, TimeUnit.SECONDS);
		startAndAwait(mover, moved, Thread.State.WAITING);
		finishOpening.countDown();

		opened.get(5, TimeUnit.SECONDS);
		moved.get(5, TimeUnit.SECONDS);
	}

	@ParameterizedTest
	@ValueSource(booleans = {true, false})
	public void testTwoPhaseMoveReleasesLocksWhenNotCommitted(boolean targetOpened) throws Exception {
		Path src = Path.of("/src").toAbsolutePath();
		Path dst = Path.of("/dst").toAbsolutePath();
		if (targetOpened) {
			inTest.getOrCreate(dst);
			Assertions.assertThrows(FileAlreadyExistsException.class, () -> inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), false));
		} else {
			inTest.prepareMove(src, dst, Mockito.mock(CryptoPath.class), false).close();
		}

		for (Path path : List.of(src, dst)) {
			Assertions.assertSame(ciphertextFileChannel, Assertions.assertTimeoutPreemptively(Duration.ofSeconds(5), () -> openChannel(path)));
		}
	}

	@Test
	public void testConcurrentOppositeTwoPhaseMovesDontDeadlock() {
		Assertions.assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
			for (int i = 0; i < 10; i++) {
				Path a = Path.of("/a" + i).toAbsolutePath();
				Path b = Path.of("/b" + i).toAbsolutePath();
				var forth = CompletableFuture.runAsync(() -> repeatTwoPhaseMove(a, b));
				var back = CompletableFuture.runAsync(() -> repeatTwoPhaseMove(b, a));
				CompletableFuture.allOf(forth, back).get();
			}
		});
	}

	private void repeatTwoPhaseMove(Path src, Path dst) {
		CryptoPath cleartextDst = Mockito.mock(CryptoPath.class);
		for (int i = 0; i < 1000; i++) {
			try (var twoPhaseMove = inTest.prepareMove(src, dst, cleartextDst, true)) {
				twoPhaseMove.commit();
			} catch (FileAlreadyExistsException e) {
				throw new IllegalStateException(e);
			}
		}
	}

	private OpenCryptoFile mockOpenCryptoFile(Path path) {
		OpenCryptoFileComponent subComponent = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile openCryptoFile = mock(OpenCryptoFile.class, path.toString());
		Mockito.when(openCryptoFileComponentFactory.create(Mockito.eq(path), Mockito.any())).thenReturn(subComponent);
		Mockito.when(subComponent.openCryptoFile()).thenReturn(openCryptoFile);
		return inTest.getOrCreate(path);
	}

	private FileChannel openChannel(Path path) throws IOException {
		return inTest.open(path, () -> inTest.newFileChannel(Mockito.mock(CryptoPath.class), path, Mockito.mock(EffectiveOpenOptions.class)));
	}

	@Test
	public void testCloseClosesRemainingOpenFiles() {
		Path path1 = Mockito.mock(Path.class, "/file1");
		Mockito.when(path1.toAbsolutePath()).thenReturn(path1);
		Mockito.when(path1.normalize()).thenReturn(path1);
		OpenCryptoFileComponent subComponent1 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file1 = mock(OpenCryptoFile.class, "file1");
		Mockito.when(openCryptoFileComponentFactory.create(Mockito.eq(path1), Mockito.any())).thenReturn(subComponent1);
		Mockito.when(subComponent1.openCryptoFile()).thenReturn(file1);
		Mockito.when(file1.getCurrentFilePath()).thenReturn(path1);

		Path path2 = Mockito.mock(Path.class, "/file2");
		Mockito.when(path2.toAbsolutePath()).thenReturn(path2);
		Mockito.when(path2.normalize()).thenReturn(path2);
		OpenCryptoFileComponent subComponent2 = mock(OpenCryptoFileComponent.class);
		OpenCryptoFile file2 = mock(OpenCryptoFile.class, "file2");
		Mockito.when(openCryptoFileComponentFactory.create(Mockito.eq(path2), Mockito.any())).thenReturn(subComponent2);
		Mockito.when(subComponent2.openCryptoFile()).thenReturn(file2);
		Mockito.when(file2.getCurrentFilePath()).thenReturn(path2);

		Assertions.assertEquals(file1, inTest.getOrCreate(path1));
		Assertions.assertEquals(file2, inTest.getOrCreate(path2));
		Assertions.assertEquals(file1, inTest.get(path1).get());
		Assertions.assertEquals(file2, inTest.get(path2).get());
		inTest.close();

		Mockito.verify(file1).close();
		Mockito.verify(file2).close();
		Assertions.assertFalse(inTest.get(path1).isPresent());
		Assertions.assertFalse(inTest.get(path2).isPresent());
	}

}
