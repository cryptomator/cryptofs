package org.cryptomator.cryptofs.migration.api;

@FunctionalInterface
public interface MigrationProgressListener {

	/**
	 * Called on every step during migration that might change the progress.
	 *
	 * @param state    Current state of the migration
	 * @param progress Progress that should be between 0.0 and 1.0 but due to inaccurate estimations it might even be 1.1
	 */
	void update(ProgressState state, double progress);

	enum ProgressState {
		/**
		 * Migration recently started. The progress can't be calculated yet.
		 */
		INITIALIZING,

		/**
		 * Migration is running and progress can be calculated.
		 * <p>
		 * Any long-running tasks should (if possible) happen in this state.
		 */
		MIGRATING,

		/**
		 * Cleanup after success or failure is running. Remaining time is in unknown.
		 */
		FINALIZING
	}

}
