plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    id("application")
    id("jacoco")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

jacoco {
    toolVersion = "0.8.12"
}

application {
    mainClass = "com.jasonernst.kanonproxy.Client"
}

dependencies {
    implementation(project(":core")) // really only for the ChangeRequest class
    implementation(libs.jna)
    implementation(libs.jnr.enxio)
    implementation(libs.knet)
    runtimeOnly(libs.logback.classic)
}