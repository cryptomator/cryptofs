package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.event.FileWriteConflictEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CiphertextWriteGuardTest {

	private static final FileTime FOREIGN_TIME = FileTime.from(Instant.parse("2031-03-04T05:06:07Z"));
	private static final FileTime VIEW_TIME = FileTime.from(Instant.parse("2029-01-02T03:04:05Z"));
	private static final FileTime CLOSE_TIME = FileTime.from(Instant.parse("2030-02-03T04:05:06Z"));

	private final Cryptor cryptor = CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_GCM).provide(new Masterkey(new byte[64]), new SecureRandom());
	private final int headerSize = cryptor.fileHeaderCryptor().headerSize();
	private final int ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
	private final int cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
	@SuppressWarnings("unchecked")
	private final Consumer<FilesystemEvent> eventConsumer = mock(Consumer.class);
	private final ChunkIO chunkIO = new ChunkIO();
	private final AtomicLong fileSize = new AtomicLong();
	private final AtomicReference<Instant> lastModified = new AtomicReference<>(Instant.ofEpochMilli(1));

	private FileSystem fileSystem;
	private Path path;
	private AtomicReference<Path> currentPath;
	private FileHeaderHolder headerHolder;
	private FileChannel channel;
	private CiphertextWriteGuard inTest;

	@BeforeEach
	void setup() throws IOException {
		fileSystem = Jimfs.newFileSystem(Configuration.unix());
		path = fileSystem.getPath("/file");
		currentPath = new AtomicReference<>(path);
		headerHolder = new FileHeaderHolder(cryptor, currentPath);
		headerHolder.createNew();
		headerHolder.headerIsPersisted().set(true);
		var header = new byte[headerSize];
		headerHolder.getEncrypted().duplicate().rewind().get(header);
		Files.write(path, header);
		channel = FileChannel.open(path, READ, WRITE);
		writeRaw(chunkPosition(0), filled(1));
		writeRaw(chunkPosition(1), filled(2));
		chunkIO.registerChannel(channel, true);
		fileSize.set(2L * cleartextChunkSize);
		inTest = new CiphertextWriteGuard(cryptor, chunkIO, headerHolder, fileSize, lastModified, eventConsumer, currentPath, new AtomicReference<CryptoPath>());
		inTest.seedSize(channel.size());
		inTest.beforeWrite(channel);
		inTest.observe(0, ByteBuffer.wrap(filled(1)));
		inTest.observe(1, ByteBuffer.wrap(filled(2)));
	}

	@AfterEach
	void tearDown() throws IOException {
		channel.close();
		fileSystem.close();
	}

	private byte[] filled(int value) {
		var bytes = new byte[ciphertextChunkSize];
		Arrays.fill(bytes, (byte) value);
		return bytes;
	}

	private long chunkPosition(long chunkIndex) {
		return headerSize + chunkIndex * ciphertextChunkSize;
	}

	private void writeRaw(long position, byte[] bytes) throws IOException {
		var buffer = ByteBuffer.wrap(bytes);
		while (buffer.hasRemaining()) {
			channel.write(buffer, position + buffer.position());
		}
	}

	private void save(long chunkIndex, int value) throws IOException {
		var ciphertext = ByteBuffer.wrap(filled(value));
		long position = chunkPosition(chunkIndex);
		inTest.guardedSave(chunkIndex, position, ciphertext, target -> {
			while (ciphertext.hasRemaining()) {
				target.write(ciphertext, position + ciphertext.position());
			}
		});
	}

	private void tornSave(long chunkIndex, int value, int completedBytes) {
		var ciphertext = ByteBuffer.wrap(filled(value));
		long position = chunkPosition(chunkIndex);
		var failure = assertThrows(IOException.class, () -> inTest.guardedSave(chunkIndex, position, ciphertext, target -> {
			target.write(ciphertext.duplicate().limit(completedBytes), position);
			ciphertext.position(completedBytes);
			throw new IOException("torn write");
		}));
		assertEquals("torn write", failure.getMessage());
	}

	private byte[] storedChunk(long chunkIndex) throws IOException {
		var buffer = ByteBuffer.allocate(ciphertextChunkSize);
		channel.read(buffer, chunkPosition(chunkIndex));
		return Arrays.copyOf(buffer.array(), buffer.position());
	}

	@ParameterizedTest(name = "{0} bytes written")
	@ValueSource(ints = {10, 100}) // fewer and more than the compared edge
	@DisplayName("a torn save is no conflict and succeeds on retry")
	void testTornSaveRetries(int completedBytes) throws IOException {
		inTest.markUnsaved(0);
		tornSave(0, 9, completedBytes);

		save(0, 9);

		assertFalse(inTest.isConflicted());
		assertArrayEquals(filled(9), storedChunk(0));
		verify(eventConsumer, never()).accept(any());
	}

	@Test
	@DisplayName("a foreign change after a torn save is refused, with one event")
	void testForeignChangeAfterTornSaveIsRefused() throws IOException {
		inTest.markUnsaved(0);
		tornSave(0, 9, 100);
		writeRaw(chunkPosition(0), new byte[]{42});

		assertThrows(FileSystemException.class, () -> save(0, 9));
		assertThrows(FileSystemException.class, () -> save(1, 9));

		assertTrue(inTest.isConflicted());
		assertEquals(42, storedChunk(0)[0]);
		assertArrayEquals(filled(2), storedChunk(1));
		verify(eventConsumer, timeout(5000)).accept(any(FileWriteConflictEvent.class));
		verify(eventConsumer, after(100)).accept(any());
	}

	@Test
	@DisplayName("a torn save of an evicted chunk extending the file is no conflict for the next save")
	void testTornSaveOfEvictedChunkIsNoConflict() throws IOException {
		inTest.markUnsaved(2);
		tornSave(2, 9, 100);
		inTest.forget(2);

		save(0, 9);

		assertFalse(inTest.isConflicted());
		assertArrayEquals(filled(9), storedChunk(0));
	}

	@Test
	@DisplayName("a torn header write is no conflict and succeeds on retry")
	void testTornHeaderRetries() throws IOException {
		channel.truncate(0);
		inTest.seedSize(0);
		headerHolder.headerIsPersisted().set(false);
		var torn = headerHolder.getEncrypted().duplicate().rewind();
		assertThrows(IOException.class, () -> inTest.guardedHeaderWrite(channel, torn, () -> {
			channel.write(torn.duplicate().limit(10), 0);
			torn.position(10);
			throw new IOException("torn write");
		}));

		var header = headerHolder.getEncrypted().duplicate().rewind();
		inTest.guardedHeaderWrite(channel, header, () -> channel.write(header, 0));

		assertFalse(inTest.isConflicted());
		assertEquals(headerSize, channel.size());
	}

	@Test
	@DisplayName("a save is refused if the header on disk changed")
	void testChangedHeaderRefusesSave() throws IOException {
		writeRaw(0, new byte[headerSize]);

		assertThrows(FileSystemException.class, () -> save(0, 9));

		assertArrayEquals(filled(1), storedChunk(0));
	}

	@Test
	@DisplayName("a save is refused if the raw size changed")
	void testChangedSizeRefusesSave() throws IOException {
		writeRaw(chunkPosition(2), filled(3));

		assertThrows(FileSystemException.class, () -> save(0, 9));

		assertArrayEquals(filled(1), storedChunk(0));
	}

	@Test
	@DisplayName("a chunk seen as absent is refused once another writer filled it")
	void testFilledAbsentChunkRefusesSave() throws IOException {
		inTest.observe(3, ByteBuffer.allocate(0));
		save(4, 5); // leaves a hole of zeros at chunk 3
		writeRaw(chunkPosition(3), new byte[]{42});

		assertThrows(FileSystemException.class, () -> save(3, 9));

		assertEquals(42, storedChunk(3)[0]);
	}

	@Test
	@DisplayName("the conflict event is delivered on another thread than the one that found the conflict")
	void testConflictEventOnOwnThread() throws IOException {
		var deliveringThread = new AtomicReference<Thread>();
		doAnswer(invocation -> {
			deliveringThread.set(Thread.currentThread());
			return null;
		}).when(eventConsumer).accept(any());
		writeRaw(0, new byte[headerSize]);

		assertThrows(FileSystemException.class, () -> save(0, 9));

		await().atMost(Duration.ofSeconds(5)).until(() -> deliveringThread.get() != null);
		assertNotSame(Thread.currentThread(), deliveringThread.get());
	}

	@Test
	@DisplayName("a truncate is refused if the raw size changed")
	void testChangedSizeRefusesTruncate() throws IOException {
		writeRaw(chunkPosition(2), filled(3));
		long foreignSize = channel.size();

		assertThrows(FileSystemException.class, () -> inTest.guardedTruncate(headerSize, channel));

		assertEquals(foreignSize, channel.size());
	}

	@Test
	@DisplayName("a truncate past the raw end changes nothing, so that a later save isn't refused")
	void testTruncatePastEndKeepsExpectedSize() throws IOException {
		long rawSize = channel.size();

		inTest.guardedTruncate(rawSize + ciphertextChunkSize, channel);

		save(0, 9);
		assertFalse(inTest.isConflicted());
		assertEquals(rawSize, channel.size());
		assertArrayEquals(filled(9), storedChunk(0));
	}

	@Test
	@DisplayName("a gap write after an adopted shrink waits for a save that holds the lock, then is refused")
	void testGapWriteWaitsForSave() throws IOException {
		channel.truncate(chunkPosition(1));
		assertTrue(inTest.beforeWrite(channel)); // adopts the shrink
		var gapWrite = new FutureTask<Void>(() -> {
			inTest.beforeGapWrite();
			return null;
		});
		var refusedDuringSave = new AtomicBoolean();
		var ciphertext = ByteBuffer.wrap(filled(9));
		long position = chunkPosition(0);

		assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
			inTest.guardedSave(0, position, ciphertext, target -> {
				var gapWriting = Thread.ofPlatform().start(gapWrite);
				await().atMost(Duration.ofSeconds(5)).until(() -> gapWriting.getState() == Thread.State.WAITING || gapWrite.isDone());
				refusedDuringSave.set(gapWrite.isDone());
				while (ciphertext.hasRemaining()) {
					target.write(ciphertext, position + ciphertext.position());
				}
			});
			var refusal = assertThrows(ExecutionException.class, () -> gapWrite.get(5, TimeUnit.SECONDS));
			assertInstanceOf(FileSystemException.class, refusal.getCause());
		});

		assertFalse(refusedDuringSave.get());
		assertArrayEquals(filled(9), storedChunk(0));
	}

	@Test
	@DisplayName("with nothing unsaved, a valid new size is adopted")
	void testBeforeWriteAdoptsValidSize() throws IOException {
		writeRaw(chunkPosition(2), filled(3));

		inTest.beforeWrite(channel);

		assertFalse(inTest.isConflicted());
		assertEquals(3L * cleartextChunkSize, fileSize.get());
	}

	@Test
	@DisplayName("with unsaved data, a new size is a conflict")
	void testBeforeWriteWithUnsavedDataRefusesNewSize() throws IOException {
		inTest.markUnsaved(0);
		writeRaw(chunkPosition(2), filled(3));

		assertThrows(FileSystemException.class, () -> inTest.beforeWrite(channel));

		assertEquals(2L * cleartextChunkSize, fileSize.get());
	}

	@Test
	@DisplayName("a completed save clears its unsaved mark, so that a later new size is adopted")
	void testCompletedSaveClearsUnsavedMark() throws IOException {
		inTest.markUnsaved(0);
		save(0, 9);
		writeRaw(chunkPosition(2), filled(3));

		assertTrue(inTest.beforeWrite(channel));

		assertEquals(3L * cleartextChunkSize, fileSize.get());
	}

	@Test
	@DisplayName("a new size that no chunks can add up to is a conflict")
	void testBeforeWriteRefusesInvalidSize() throws IOException {
		writeRaw(chunkPosition(2), new byte[ciphertextChunkSize - cleartextChunkSize]);

		assertThrows(FileSystemException.class, () -> inTest.beforeWrite(channel));
	}

	@Test
	@DisplayName("a save completing while a read samples the raw size causes no false EOF")
	void testSaveDuringReadableSizeGivesNoFalseEof() throws IOException {
		inTest.markUnsaved(2);
		FileChannel reading = mock(FileChannel.class);
		when(reading.size()).thenAnswer(invocation -> {
			long sizeBeforeSave = channel.size();
			save(2, 3);
			return sizeBeforeSave;
		});

		long readable = inTest.readableSize(reading, 3L * cleartextChunkSize);

		assertEquals(3L * cleartextChunkSize, readable);
	}

	@Test
	@DisplayName("a raw size below the last save drops unsaved chunks from the read bound")
	void testShrunkenFileDropsUnsavedFromBound() throws IOException {
		inTest.markUnsaved(1);
		channel.truncate(chunkPosition(1));

		long readable = inTest.readableSize(channel, 2L * cleartextChunkSize);

		assertEquals(cleartextChunkSize, readable);
	}

	@Test
	@DisplayName("once conflicted, unsaved chunks no longer extend the read bound")
	void testConflictDropsUnsavedFromBound() throws IOException {
		inTest.markUnsaved(2);
		writeRaw(0, new byte[headerSize]);
		assertThrows(FileSystemException.class, () -> save(0, 9));

		long readable = inTest.readableSize(channel, 3L * cleartextChunkSize);

		assertEquals(2L * cleartextChunkSize, readable);
	}

	@Test
	@DisplayName("a foreign time change before an own save keeps that save's time from being persisted, but not a later save's")
	void testForeignTimeBeforeSaveBlocksPersisting() throws IOException {
		Files.setLastModifiedTime(path, FOREIGN_TIME);

		save(0, 9);

		assertNull(persistedModifiedTime());
		save(1, 9);
		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("a time set through the view clears a foreign time change, so that a later own save's time persists")
	void testViewTimeClearsForeignTimeChange() throws IOException {
		Files.setLastModifiedTime(path, FOREIGN_TIME);
		save(0, 9);

		inTest.persistViewTimes(path, VIEW_TIME, () -> Files.setLastModifiedTime(path, VIEW_TIME));

		assertEquals(VIEW_TIME.toInstant(), lastModified.get());
		lastModified.set(Instant.ofEpochMilli(1)); // the time of the later save's edit
		save(1, 9);
		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("a time set through the view on a path the file moved away from is written, but becomes neither its time nor its time baseline")
	void testViewTimeAfterMoveIsNotAdopted() throws IOException {
		save(0, 9);
		var moved = fileSystem.getPath("/moved");
		Files.move(path, moved);
		currentPath.set(moved);
		Files.write(path, new byte[0]); // a replacement at the path the view resolved
		Files.setLastModifiedTime(moved, FOREIGN_TIME);

		inTest.persistViewTimes(path, VIEW_TIME, () -> Files.setLastModifiedTime(path, VIEW_TIME));

		assertEquals(VIEW_TIME, Files.getLastModifiedTime(path));
		assertEquals(Instant.ofEpochMilli(1), lastModified.get());
		assertNull(persistedModifiedTime()); // closing doesn't roll back the moved file's foreign time
	}

	@Test
	@DisplayName("a time set through the view on the file's path stays its own when the file moves during the write")
	void testViewTimeBeforeMoveIsAdopted() throws IOException {
		save(0, 9);
		var moved = fileSystem.getPath("/moved");

		inTest.persistViewTimes(path, VIEW_TIME, () -> {
			Files.setLastModifiedTime(path, VIEW_TIME);
			Files.move(path, moved);
			currentPath.set(moved);
		});

		assertEquals(VIEW_TIME.toInstant(), lastModified.get());
		assertEquals(VIEW_TIME, persistedModifiedTime()); // closing keeps the view time, as it is no foreign change
	}

	@Test
	@DisplayName("a time set through the view on a file detached meanwhile is written, but doesn't become its time")
	void testViewTimeOfDetachedFileIsNotAdopted() throws IOException {
		currentPath.set(null);

		inTest.persistViewTimes(path, VIEW_TIME, () -> Files.setLastModifiedTime(path, VIEW_TIME));

		assertEquals(VIEW_TIME, Files.getLastModifiedTime(path));
		assertEquals(Instant.ofEpochMilli(1), lastModified.get());
	}

	@Test
	@DisplayName("a time set through the view becomes the file's own only once it was written")
	void testFailedViewTimeIsNotAdopted() {
		var failure = assertThrows(IOException.class, () -> inTest.persistViewTimes(path, VIEW_TIME, () -> {
			throw new IOException("fail");
		}));

		assertEquals("fail", failure.getMessage());
		assertEquals(Instant.ofEpochMilli(1), lastModified.get());
	}

	@Test
	@DisplayName("persisting the times without a modification time leaves own changes pending")
	void testTimesWithoutModifiedTimeKeepOwnChangesPending() throws IOException {
		save(0, 9);
		var written = new AtomicReference<>(FOREIGN_TIME);

		inTest.persistOwnTimes(false, written::set);

		assertNull(written.get());
		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("a conflict that kept the time on disk still keeps an own save's time from being persisted")
	void testConflictKeepingTimeBlocksPersisting() throws IOException {
		save(0, 9);
		var timeAfterSave = Files.getLastModifiedTime(path);
		writeRaw(0, new byte[headerSize]);
		Files.setLastModifiedTime(path, timeAfterSave); // e.g. a sync client keeping the source's time

		assertThrows(FileSystemException.class, () -> save(1, 9));

		assertNull(persistedModifiedTime());
	}

	@Test
	@DisplayName("a failed time write leaves own changes pending, so that a retry still writes the own time")
	void testFailedTimesWriteKeepsOwnChangesPending() throws IOException {
		save(0, 9);

		assertThrows(IOException.class, () -> inTest.persistOwnTimes(true, _ -> {
			throw new IOException("fail");
		}));

		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("persisting the times holds the lock across the write, so that no save lands in between")
	void testPersistTimesHoldsLockAcrossWrite() throws IOException, InterruptedException, ExecutionException, TimeoutException {
		var concurrentSave = new FutureTask<Void>(() -> {
			save(1, 9);
			return null;
		});
		var savedDuringWrite = new AtomicBoolean();

		inTest.persistOwnTimes(true, _ -> {
			var saving = Thread.ofPlatform().start(concurrentSave);
			await().atMost(Duration.ofSeconds(5)).until(() -> saving.getState() == Thread.State.WAITING || concurrentSave.isDone());
			savedDuringWrite.set(concurrentSave.isDone());
		});

		concurrentSave.get(5, TimeUnit.SECONDS);
		assertFalse(savedDuringWrite.get());
		assertArrayEquals(filled(9), storedChunk(1));
	}

	@Test
	@DisplayName("a time the file system sets while closing a channel after an own save stays the file's own")
	void testCloseTimeAfterOwnSaveIsOwn() throws IOException {
		save(0, 9);

		inTest.guardedClose(() -> Files.setLastModifiedTime(path, CLOSE_TIME)); // like Windows, which may set the time once a written handle closes

		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("a time the file system sets while closing a channel after the own time was persisted is set back to it")
	void testCloseTimeAfterPersistedOwnTimeIsOwn() throws IOException {
		save(0, 9);
		assertEquals(FileTime.fromMillis(1), persistedModifiedTime()); // e.g. force(true) before closing

		inTest.guardedClose(() -> Files.setLastModifiedTime(path, CLOSE_TIME));

		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
	}

	@Test
	@DisplayName("a close that leaves the time alone leaves nothing to persist once the own time was persisted")
	void testUnchangedCloseTimeAfterPersistedOwnTime() throws IOException {
		save(0, 9);
		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());

		inTest.guardedClose(() -> {});

		assertNull(persistedModifiedTime());
	}

	@Test
	@DisplayName("a foreign time change before closing a channel still keeps an own save's time from being persisted")
	void testForeignTimeBeforeCloseBlocksPersisting() throws IOException {
		save(0, 9);
		Files.setLastModifiedTime(path, FOREIGN_TIME);

		inTest.guardedClose(() -> Files.setLastModifiedTime(path, CLOSE_TIME));

		assertNull(persistedModifiedTime());
	}

	private FileTime persistedModifiedTime() throws IOException {
		var written = new AtomicReference<FileTime>();
		inTest.persistOwnTimes(true, written::set);
		return written.get();
	}

	@Test
	@DisplayName("an own save may persist its time once")
	void testOwnSaveMayPersistItsTimeOnce() throws IOException {
		save(0, 9);

		assertEquals(FileTime.fromMillis(1), persistedModifiedTime());
		assertNull(persistedModifiedTime());
	}

	@Test
	@DisplayName("a detached file keeps naming its last path, also after a second detach")
	void testCiphertextPathAfterDetach() {
		var movedPath = fileSystem.getPath("/moved");
		currentPath.set(movedPath);
		inTest.rememberPaths();
		currentPath.set(null);
		inTest.rememberPaths();

		assertEquals(movedPath, inTest.ciphertextPath());
	}

	@Test
	@DisplayName("the conflict event names the last path of a detached file")
	void testConflictEventNamesDetachedPath() throws IOException {
		inTest.rememberPaths();
		currentPath.set(null);
		writeRaw(0, new byte[headerSize]);

		assertThrows(FileSystemException.class, () -> save(0, 9));

		var captor = org.mockito.ArgumentCaptor.forClass(FilesystemEvent.class);
		verify(eventConsumer, timeout(5000)).accept(captor.capture());
		assertEquals(path, assertInstanceOf(FileWriteConflictEvent.class, captor.getValue()).ciphertextPath());
	}
}
