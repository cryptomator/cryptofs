package org.cryptomator.cryptofs.fh;

import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.util.stream.Stream;

import static org.cryptomator.cryptofs.matchers.ByteBufferMatcher.contains;
import static org.cryptomator.cryptofs.util.ByteBuffers.repeat;
import static org.hamcrest.Matchers.is;

public class ChunkDataTest {

	private static final int SIZE = 200;

	public static Stream<WayToCreateEmptyChunkData> waysToCreateEmptyChunkData() {
		return Stream.of(
				new CreateEmptyChunkData(), //
				new WrapEmptyBuffer() //
		);
	}

	public static Stream<WayToCreateChunkDataWithContent> waysToCreateChunkDataWithContent() { //
		return Stream.of(
				new WrapBuffer(), //
				new CreateEmptyChunkDataAndCopyFromBuffer(), //
				new WrapEmptyBufferAndCopyFromBuffer(), //
				new WrapPartOfBufferAndCopyRemainingFromBuffer() //
		);
	}

	@Test
	public void testChunkDataWrappingBufferIsNotDirty() {
		ByteBuffer buffer = repeat(3).times(200).asByteBuffer();

		ChunkData inTest = ChunkData.wrap(buffer);

		Assertions.assertFalse(inTest.isDirty());
	}

	@Test
	public void testEmptyChunkDataIsNotDirty() {
		ChunkData inTest = ChunkData.emptyWithSize(200);

		Assertions.assertFalse(inTest.isDirty());
	}

	@Test
	public void testWrittenChunkDataIsDirty() {
		ChunkData inTest = ChunkData.emptyWithSize(200);
		inTest.copyData().from(repeat(3).times(200).asByteBuffer());

		Assertions.assertTrue(inTest.isDirty());
	}

	@Test
	public void testToString() {
		ChunkData inTest = ChunkData.emptyWithSize(150);
		inTest.copyDataStartingAt(50).from(repeat(3).times(50).asByteBuffer());

		MatcherAssert.assertThat(inTest.toString(), is("ChunkData(dirty: true, length: 100, capacity: 150)"));
	}

	@ParameterizedTest
	@MethodSource("waysToCreateEmptyChunkData")
	public void testAsReadOnlyBufferReturnsEmptyBufferIfEmpty(WayToCreateEmptyChunkData wayToCreateEmptyChunkData) {
		ChunkData inTest = wayToCreateEmptyChunkData.create();

		MatcherAssert.assertThat(inTest.asReadOnlyBuffer(), contains(new byte[0]));
	}

	@ParameterizedTest
	@MethodSource("waysToCreateChunkDataWithContent")
	public void testAsReadOnlyBufferReturnsContent(WayToCreateChunkDataWithContent wayToCreateChunkDataWithContent) {
		ChunkData inTest = wayToCreateChunkDataWithContent.create(repeat(3).times(SIZE).asByteBuffer());

		MatcherAssert.assertThat(inTest.asReadOnlyBuffer(), contains(repeat(3).times(SIZE).asByteBuffer()));
	}

	@ParameterizedTest
	@MethodSource("waysToCreateChunkDataWithContent")
	public void testCopyToCopiesContent(WayToCreateChunkDataWithContent wayToCreateChunkDataWithContent) {
		ChunkData inTest = wayToCreateChunkDataWithContent.create(repeat(3).times(SIZE).asByteBuffer());
		ByteBuffer target = ByteBuffer.allocate(200);

		inTest.copyData().to(target);
		target.flip();

		MatcherAssert.assertThat(target, contains(repeat(3).times(SIZE).asByteBuffer()));
	}

	@ParameterizedTest
	@MethodSource("waysToCreateEmptyChunkData")
	public void testCopyToCopiesNothingIfEmpty(WayToCreateEmptyChunkData wayToCreateEmptyChunkData) {
		ChunkData inTest = wayToCreateEmptyChunkData.create();
		ByteBuffer target = ByteBuffer.allocate(SIZE);

		inTest.copyData().to(target);

		MatcherAssert.assertThat(target, contains(repeat(0).times(SIZE).asByteBuffer()));
	}

	@ParameterizedTest
	@MethodSource("waysToCreateChunkDataWithContent")
	public void testCopyToWithOffsetCopiesContentFromOffset(WayToCreateChunkDataWithContent wayToCreateChunkDataWithContent) {
		int offset = 70;
		ChunkData inTest = wayToCreateChunkDataWithContent.create(repeat(3).times(SIZE).asByteBuffer());
		ByteBuffer target = ByteBuffer.allocate(SIZE);

		inTest.copyDataStartingAt(offset).to(target);

		target.limit(SIZE - offset);
		target.position(0);
		MatcherAssert.assertThat(target, contains(repeat(3).times(SIZE - offset).asByteBuffer()));
		target.limit(SIZE);
		target.position(SIZE - offset);
		MatcherAssert.assertThat(target, contains(repeat(0).times(offset).asByteBuffer()));
	}

	interface WayToCreateEmptyChunkData {

		ChunkData create();

	}

	interface WayToCreateChunkDataWithContent {

		ChunkData create(ByteBuffer content);

	}

	private static class CreateEmptyChunkData implements WayToCreateEmptyChunkData {

		@Override
		public ChunkData create() {
			return ChunkData.emptyWithSize(SIZE);
		}

		@Override
		public String toString() {
			return "CreateEmptyChunkData";
		}

	}

	private static class WrapEmptyBuffer implements WayToCreateEmptyChunkData {

		@Override
		public ChunkData create() {
			ByteBuffer buffer = ByteBuffer.allocate(SIZE);
			buffer.limit(0);
			return ChunkData.wrap(buffer);
		}

		@Override
		public String toString() {
			return "WrapEmptyBuffer";
		}

	}

	private static class WrapBuffer implements WayToCreateChunkDataWithContent {

		@Override
		public ChunkData create(ByteBuffer content) {
			return ChunkData.wrap(content);
		}

		@Override
		public String toString() {
			return "WrapBuffer";
		}

	}

	private static class CreateEmptyChunkDataAndCopyFromBuffer implements WayToCreateChunkDataWithContent {

		@Override
		public ChunkData create(ByteBuffer content) {
			ChunkData result = ChunkData.emptyWithSize(content.remaining());
			result.copyData().from(content);
			return result;
		}

		@Override
		public String toString() {
			return "CreateEmptyChunkDataAndCopyFromBuffer";
		}

	}

	private static class WrapEmptyBufferAndCopyFromBuffer implements WayToCreateChunkDataWithContent {

		@Override
		public ChunkData create(ByteBuffer content) {
			ByteBuffer buffer = ByteBuffer.allocate(content.remaining());
			buffer.limit(0);
			ChunkData result = ChunkData.wrap(buffer);
			result.copyData().from(content.asReadOnlyBuffer());
			return result;
		}

		@Override
		public String toString() {
			return "WrapEmptyBufferAndCopyFromBuffer";
		}

	}

	private static class WrapPartOfBufferAndCopyRemainingFromBuffer implements WayToCreateChunkDataWithContent {

		@Override
		public ChunkData create(ByteBuffer content) {
			int position = content.position();
			int remaining = content.remaining();
			int halfRemaining = remaining / 2;

			ByteBuffer readOnlyContent = content.asReadOnlyBuffer();
			readOnlyContent.limit(position + halfRemaining);
			ByteBuffer wrappedContent = ByteBuffer.allocate(remaining);
			wrappedContent.put(readOnlyContent);
			wrappedContent.limit(halfRemaining);
			ChunkData result = ChunkData.wrap(wrappedContent);

			readOnlyContent.limit(position + remaining);
			result.copyDataStartingAt(halfRemaining).from(readOnlyContent);

			return result;
		}

		@Override
		public String toString() {
			return "WrapPartOfBufferAndCopyRemainingFromBuffer";
		}

	}

}
