pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    // The Compose compiler plugin's marker artifact is not in this machine's
    // Gradle cache, but the plugin module itself is, so resolve the plugin id
    // straight to its coordinates. Offline builds then work without a download.
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id == "org.jetbrains.kotlin.plugin.compose") {
                useModule("org.jetbrains.kotlin:compose-compiler-gradle-plugin:2.2.10")
            }
        }
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "p2pdemo"
include(":app")
