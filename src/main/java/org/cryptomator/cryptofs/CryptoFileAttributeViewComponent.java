package org.cryptomator.cryptofs;

import dagger.BindsInstance;
import dagger.Subcomponent;

import java.nio.file.LinkOption;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;
import java.util.Set;

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

		@BindsInstance
		Builder linkOptions(LinkOption[] linkOptions);

		CryptoFileAttributeViewComponent build();
	}

}



