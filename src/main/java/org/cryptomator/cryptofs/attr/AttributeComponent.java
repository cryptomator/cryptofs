package org.cryptomator.cryptofs.attr;

import dagger.BindsInstance;
import dagger.Subcomponent;
import org.cryptomator.cryptofs.common.CiphertextFileType;

import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

@AttributeScoped
@Subcomponent(modules = {AttributeModule.class})
public interface AttributeComponent {

	Optional<BasicFileAttributes> attributes();

	@Subcomponent.Builder
	interface Builder {

		@BindsInstance
		Builder type(Class<? extends BasicFileAttributes> type);

		@BindsInstance
		Builder ciphertextPath(Path ciphertextPath);

		@BindsInstance
		Builder ciphertextFileType(CiphertextFileType ciphertextFileType);

		@BindsInstance
		Builder ciphertextAttributes(BasicFileAttributes ciphertextAttributes);

		AttributeComponent build();
	}
}
