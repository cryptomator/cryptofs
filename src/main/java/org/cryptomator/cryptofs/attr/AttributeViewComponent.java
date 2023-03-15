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

	@Subcomponent.Factory
	interface Factory {

		AttributeViewComponent create(@BindsInstance CryptoPath cleartextPath, @BindsInstance Class<? extends FileAttributeView> type, @BindsInstance LinkOption[] linkOptions);

	}

}



