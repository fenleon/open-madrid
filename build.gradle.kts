import org.gradle.api.publish.maven.MavenPublication

plugins {
    id("com.android.application") version "8.12.3" apply false
    id("org.jetbrains.kotlin.android") version "2.3.20" apply false
}

// JitPack publishing: a tag build runs publishToMavenLocal on every module.
// Consumers take com.github.fenleon.open-madrid:<module>:<tag>.
subprojects {
    apply(plugin = "maven-publish")
    group = "com.github.fenleon"
    version = "0.1.0"
    afterEvaluate {
        // :engine (Android library) publishes itself in its own build file —
        // the AGP release component is not visible from the root callback.
        if (components.findByName("java") != null) {
            extensions.configure<PublishingExtension> {
                publications {
                    create<MavenPublication>("maven") {
                        from(components["java"])
                    }
                }
            }
        }
    }
}
