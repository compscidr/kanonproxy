plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    id("application")
    id("jacoco")
}

tasks.withType<Test>().configureEach {
    finalizedBy("jacocoTestReport")
    testLogging {
        // get the test stdout / stderr to show up when we run gradle from command line
        // https://itecnote.com/tecnote/gradle-how-to-get-output-from-test-stderr-stdout-into-console/
        // https://developer.android.com/studio/test/advanced-test-setup
        // https://docs.gradle.org/current/javadoc/org/gradle/api/tasks/testing/Test.html
        outputs.upToDateWhen {true}
        showStandardStreams = true
    }
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
    implementation(libs.jna)
    implementation(libs.jnr.enxio)
    implementation(libs.knet)
    runtimeOnly(libs.logback.classic)
    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.jupiter.engine)
}