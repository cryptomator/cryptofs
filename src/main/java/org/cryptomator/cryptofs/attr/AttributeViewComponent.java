package org.cryptomator.cryptofs.attr;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.CryptoPath;

import java.nio.file.LinkOption;
import java.nio.file.attribute.FileAttributeView;
import java.util.Optional;

@AttributeViewScoped
@Subcomponent(modules = {AttributeViewModule.class})
public interface AttributeViewComponent {

	Optional<FileAttributeView> attributeView();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder cleartextPath(CryptoPath cleartextPath);

		@BindsInstance
		Builder viewType(Class<? extends FileAttributeView> type);

		@BindsInstance
		Builder linkOptions(LinkOption[] linkOptions);

		AttributeViewComponent build();
	}

}



