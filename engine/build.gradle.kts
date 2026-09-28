plugins {
    id("com.android.library") // version inherited from the root classpath (AGP 8.12.3)
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.fenn.imessage.engine"
    compileSdk = 36

    defaultConfig {
        minSdk = 34
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // The ported components are part of :engine's public API surface (Engine exposes
    // IdsStore, CourierClient config/frames, LookupConfig, envelope types directly).
    api(project(":codec"))
    api(project(":courier"))
    api(project(":ids"))
    api(project(":crypto"))
    api(project(":registration"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(kotlin("test"))
}

// Host-side live-probe runner (explicit network use only — never run by `test`).
// Usage from the workspace root:
//   tools/build --force --dir imessage :engine:runProbe
// Optional fixture dir override: -PprobeArgs=codec/src/test/resources/imessage
val probeRuntime by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}

dependencies {
    probeRuntime(libs.kotlinx.coroutines.core)
    probeRuntime(project(":codec", configuration = "runtimeElements"))
    probeRuntime(project(":ids", configuration = "runtimeElements"))
}

tasks.register<JavaExec>("runProbe") {
    group = "probe"
    description = "Run the authorized live IDS/APNs bag + courier TLS probes (GETs only)."
    dependsOn("compileDebugUnitTestKotlin")
    mainClass.set("dev.fenn.imessage.engine.probe.ProbeMainKt")
    classpath = files(
        probeRuntime,
        layout.buildDirectory.dir("tmp/kotlin-classes/debug"),
        layout.buildDirectory.dir("tmp/kotlin-classes/debugUnitTest"),
    )
    workingDir = rootDir
    args = (findProperty("probeArgs") as String?)?.split(" ")?.filter { it.isNotBlank() } ?: emptyList()
}
