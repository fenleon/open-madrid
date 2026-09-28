plugins {
    kotlin("jvm") // version inherited from the root classpath (kotlin-gradle-plugin 2.3.20)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":codec"))
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(kotlin("test"))
}
