package org.cryptomator.cryptofs.migration.api;

@FunctionalInterface
public interface MigrationContinuationListener {

	/**
	 * Invoked when the migration requires action.
	 * <p>
	 * This method is invoked on the thread that runs the migration.
	 * If you want to perform longer-running actions such as waiting for user feedback on the UI thread,
	 * consider subclassing {@link SimpleMigrationContinuationListener}.
	 * 
	 * @param event The migration event that occurred
	 * @see SimpleMigrationContinuationListener
	 * @return How to proceed with the migration
	 */
	ContinuationResult continueMigrationOnEvent(ContinuationEvent event);
	
	enum ContinuationResult {
		CANCEL, PROCEED
	}
	
	enum ContinuationEvent {
		/**
		 * Migrator wants to do a full recursive directory listing. This might take a while.
		 */
		REQUIRES_FULL_VAULT_DIR_SCAN
	}
	
}
