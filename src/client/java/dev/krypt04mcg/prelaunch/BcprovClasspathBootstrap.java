package dev.krypt04mcg.prelaunch;
import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.entrypoint.PreLaunchEntrypoint;
import net.fabricmc.loader.impl.launch.FabricLauncherBase;

import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public final class BcprovClasspathBootstrap
        implements PreLaunchEntrypoint {

    @Override
    public void onPreLaunch() {
        Path library = FabricLoader.getInstance()
                .getGameDir()
                .resolve(".krypt04mcg-libs")
                .resolve("bcprov.jar");

        try {
            Files.createDirectories(library.getParent());

            try (InputStream input =
                    BcprovClasspathBootstrap.class.getResourceAsStream(
                            "/META-INF/krypt04mcg-libs/bcprov.jar")) {

                if (input == null) {
                    throw new IOException("Embedded bcprov.jar not found");
                }

                Files.copy(
                        input,
                        library,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }

            
            FabricLauncherBase.getLauncher()
                    .addToClassPath(library);

        } catch (IOException e) {
            throw new RuntimeException(
                    "Failed to load embedded Bouncy Castle", e
            );
        }
    }
}