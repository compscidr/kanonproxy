plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    id("application")
    id("jacoco")
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    jvmToolchain(21)
}

jacoco {
    toolVersion = "0.8.12"
}

application {
    mainClass = "com.jasonernst.kanonproxy.Server"
}

dependencies {
    implementation(project(":core"))
    implementation(libs.knet)
    implementation(libs.icmp.linux)
    runtimeOnly(libs.logback.classic)
}