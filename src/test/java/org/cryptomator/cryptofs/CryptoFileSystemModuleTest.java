package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.event.ConflictResolutionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.cryptomator.cryptofs.inuse.StubInUseManager;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CryptoFileSystemModuleTest {

	CryptoFileSystemModule inTest = new CryptoFileSystemModule();

	@Test
	void testEventConsumerIsDecorated() {
		var p = Mockito.mock(Path.class);
		var event = new ConflictResolutionFailedEvent(p, p, new RuntimeException());
		var eventConsumer = (Consumer<FilesystemEvent>) mock(Consumer.class);
		doThrow(new RuntimeException("fail")).when(eventConsumer).accept(event);
		var props = mock(CryptoFileSystemProperties.class);
		when(props.filesystemEventConsumer()).thenReturn(eventConsumer);

		var decoratedConsumer = inTest.provideFilesystemEventConsumer(props);
		Assertions.assertDoesNotThrow(() -> decoratedConsumer.accept(event));
		verify(eventConsumer).accept(event);
	}

	@Test
	void testInUseManagerIsStubOnReadOnly() {
		var cryptor = Mockito.mock(Cryptor.class);
		var props = mock(CryptoFileSystemProperties.class);
		when(props.readonly()).thenReturn(true);
		var result = inTest.provideInUseManager(props, Optional.of("someOwner"), cryptor);

		Assertions.assertInstanceOf(StubInUseManager.class, result);
	}

	@ParameterizedTest
	@DisplayName("If ownerGetter returns null or blank, return empty optional")
	@ValueSource(strings = {" \t "})
	@NullSource
	void testOwnerIsBlankOrNull(String input) {
		Supplier<String> ownerGetter = () -> input;
		var props = mock(CryptoFileSystemProperties.class);
		when(props.ownerGetter()).thenReturn(ownerGetter);
		var result = inTest.provideFsOwner(props);

		Assertions.assertTrue(result.isEmpty());
	}

	@ParameterizedTest
	@DisplayName("Filesystem owner is always less than 100 chars")
	@MethodSource("provideArgsForOwnerIsInsideBounds")
	void testOwnerIsInsideBounds(String input, int expectedLength) {
		Supplier<String> ownerGetter = () -> input;
		var props = mock(CryptoFileSystemProperties.class);
		when(props.ownerGetter()).thenReturn(ownerGetter);
		var result = inTest.provideFsOwner(props);

		Assertions.assertTrue(result.isPresent());
		Assertions.assertEquals(expectedLength, result.get().length());
	}

	private static Stream<Arguments> provideArgsForOwnerIsInsideBounds() {
		return Stream.of(
				Arguments.of("a", 1),
				Arguments.of("b".repeat(101), 100)
		);
	}
}
