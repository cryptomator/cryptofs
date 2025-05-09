package org.cryptomator.cryptofs.event;

import java.time.Instant;
import java.util.function.Consumer;

/**
 * Common interface for all filesystem events.
 * <p>
 * Events are emitted via the notification method set in the properties during filesystem creation, see {@link org.cryptomator.cryptofs.CryptoFileSystemProperties.Builder#withFilesystemEventConsumer(Consumer)}.
 * <p>
 * To get a specific event type, use the enhanced switch pattern or typecasting in if-instance of, e.g.
 * {@code
 * FilesystemEvent fse;
 * switch (fse) {
 *   case ConflictResolvedEvent e -> //do other stuff
 *   case DecryptionFailedEvent(Instant timestamp, Path ciphertext, Exception ex)  -> //do stuff
 *   //... other cases
 * }
 * if( fse instanceof DecryptionFailedEvent(Instant timestamp, Path ciphertext, Exception ex) {
 *   //do more stuff
 * }
 * }.
 *
 * @apiNote Events might have occured a long time ago in a galaxy far, far away... therefore, any feedback method is non-blocking and might fail due to changes in the filesystem.
 */
public sealed interface FilesystemEvent permits BrokenDirFileEvent, BrokenFileNodeEvent, ConflictResolutionFailedEvent, ConflictResolvedEvent, DecryptionFailedEvent {

	/**
	 * Gets the timestamp when the event occurred.
	 *
	 * @return the event timestamp as an {@link Instant}
	 */
	Instant getTimestamp();
}
