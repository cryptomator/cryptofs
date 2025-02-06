package org.cryptomator.cryptofs;

import org.cryptomator.cryptofs.event.ConflictResolutionFailedEvent;
import org.cryptomator.cryptofs.event.FilesystemEvent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.util.function.Consumer;

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

}
