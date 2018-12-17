package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;

import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

@PerAttributeView
@Subcomponent(modules = {CryptoFileAttributeViewModule.class})
interface CryptoFileAttributeViewComponent {

	Optional<FileAttributeView> attributeView();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder cleartextPath(CryptoPath cleartextPath);

		@BindsInstance
		Builder viewType(Class<? extends FileAttributeView> type);

		CryptoFileAttributeViewComponent build();
	}

}



