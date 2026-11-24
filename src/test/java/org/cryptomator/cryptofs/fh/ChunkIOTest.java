package org.cryptomator.cryptofs.fh;

import com.google.common.jimfs.Configuration;
import com.google.common.jimfs.Jimfs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.channels.NonWritableChannelException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;

import static java.nio.file.StandardOpenOption.READ;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class ChunkIOTest {

	private final ChunkIO inTest = new ChunkIO();

	private FileSystem fileSystem;
	private Path path;

	@BeforeEach
	void setup() throws IOException {
		fileSystem = Jimfs.newFileSystem(Configuration.unix());
		path = fileSystem.getPath("/file");
		Files.write(path, new byte[]{1, 2, 3});
	}

	@AfterEach
	void tearDown() throws IOException {
		fileSystem.close();
	}

	private FileChannel closedChannel() throws IOException {
		var channel = FileChannel.open(path, READ, WRITE);
		channel.close();
		return channel;
	}

	@Test
	@DisplayName("a closed channel that is still registered is neither read from nor written through, which fails as a closed channel")
	void testClosedChannelIsNotSelected() throws IOException {
		inTest.registerChannel(closedChannel(), true);

		assertThrows(ClosedChannelException.class, () -> inTest.read(ByteBuffer.allocate(3), 0));
		assertThrows(ClosedChannelException.class, inTest::getWritableChannel);
	}

	@Test
	@DisplayName("without a registered channel, reading and writing fail as not permitted")
	void testNoRegisteredChannel() throws IOException {
		try (var readOnly = FileChannel.open(path, READ)) {
			inTest.registerChannel(readOnly, false);

			assertThrows(NonWritableChannelException.class, inTest::getWritableChannel);
			inTest.unregisterChannel(readOnly);
			var buf = ByteBuffer.allocate(3);
			assertThrows(NonReadableChannelException.class, () -> inTest.read(buf, 0));
		}
	}

	@Test
	@DisplayName("an open channel registered next to closed ones is read from and written through")
	void testOpenChannelIsSelected() throws IOException {
		for (int i = 0; i < 5; i++) {
			inTest.registerChannel(closedChannel(), true);
		}
		try (var open = FileChannel.open(path, READ, WRITE)) {
			inTest.registerChannel(open, true);
			var dst = ByteBuffer.allocate(3);

			assertEquals(3, inTest.read(dst, 0));
			assertArrayEquals(new byte[]{1, 2, 3}, dst.array());
			assertSame(open, inTest.getWritableChannel());
		}
	}

}
