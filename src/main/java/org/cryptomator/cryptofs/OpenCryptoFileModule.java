package org.cryptomator.cryptofs;

import java.nio.file.Path;

import dagger.Module;
import dagger.Provides;

@Module
class OpenCryptoFileModule {

	private final Path path;
	private final EffectiveOpenOptions options;
	private final Runnable onClose;

	private OpenCryptoFileModule(Builder builder) {
		this.path = builder.path;
		this.onClose = builder.onClose;
		this.options = builder.options;
	}

	@Provides
	@PerOpenFile
	@OpenFilePath
	public Path providePath() {
		return path;
	}

	@Provides
	@PerOpenFile
	@OpenFileOnCloseHandler
	public Runnable provideOnClose() {
		return onClose;
	}

	@Provides
	@PerOpenFile
	public EffectiveOpenOptions provideOptions() {
		return options;
	}

	public static Builder openCryptoFileModule() {
		return new Builder();
	}

	public static class Builder {

		private Path path;
		private Runnable onClose;
		private EffectiveOpenOptions options;

		private Builder() {
		}

		public Builder withPath(Path path) {
			this.path = path;
			return this;
		}

		public Builder onClose(Runnable onClose) {
			this.onClose = onClose;
			return this;
		}

		public Builder withOptions(EffectiveOpenOptions options) {
			this.options = options;
			return this;
		}

		public OpenCryptoFileModule build() {
			validate();
			return new OpenCryptoFileModule(this);
		}

		private void validate() {
			if (path == null) {
				throw new IllegalStateException("path must be set");
			}
			if (options == null) {
				throw new IllegalStateException("options must be set");
			}
			if (onClose == null) {
				throw new IllegalStateException("onClose must be set");
			}
		}

	}

}
