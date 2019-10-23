package org.cryptomator.cryptofs.dir;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.CryptoPath;
import org.cryptomator.cryptofs.CryptoPathMapper;

import javax.inject.Named;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.function.Consumer;

@DirectoryStreamScoped
@Subcomponent
public interface DirectoryStreamComponent {

	CryptoDirectoryStream directoryStream();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder cleartextPath(@Named("cleartextPath") Path cleartextPath);

		@BindsInstance
		Builder dirId(@Named("dirId") String dirId);

		@BindsInstance
		Builder ciphertextDirectoryStream(DirectoryStream<Path> ciphertextDirectoryStream);

		@BindsInstance
		Builder filter(DirectoryStream.Filter<? super Path> filter);

		@BindsInstance
		Builder onClose(Consumer<CryptoDirectoryStream> onClose);

		DirectoryStreamComponent build();
	}

}



