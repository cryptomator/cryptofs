package org.cryptomator.cryptofs.dir;

import dagger.BindsInstance;
import dagger.Subcomponent;

import jakarta.inject.Named;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.function.Consumer;

@DirectoryStreamScoped
@Subcomponent
public interface DirectoryStreamComponent {

	CryptoDirectoryStream directoryStream();

	@Subcomponent.Factory
	interface Factory {

		DirectoryStreamComponent create(@BindsInstance @Named("cleartextPath") Path cleartextPath, //
										@BindsInstance @Named("dirId") String dirId, //
										@BindsInstance DirectoryStream<Path> ciphertextDirectoryStream, //
										@BindsInstance DirectoryStream.Filter<? super Path> filter, //
										@BindsInstance Consumer<CryptoDirectoryStream> onClose);
	}

}



