plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    id("java-library")
    id("jacoco")
    alias(libs.plugins.git.version)
    alias(libs.plugins.sonatype.maven.central)
    alias(libs.plugins.gradleup.nmcp.aggregation)
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
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    jvmToolchain(21)
}

jacoco {
    toolVersion = "0.8.13"
}

dependencies {
    implementation(project(":core")) // only really for the DEFAULT_PORT
    implementation(libs.jna)
    implementation(libs.jnr.enxio)
    implementation(libs.knet)
    runtimeOnly(libs.logback.classic)
    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.jupiter.engine)
}

version = "0.0.0-SNAPSHOT"
gitVersioning.apply {
    refs {
        branch(".+") { version = "\${ref}-SNAPSHOT" }
        tag("v(?<version>.*)") { version = "\${ref.version}" }
    }
}

// see: https://github.com/vanniktech/gradle-maven-publish-plugin/issues/747#issuecomment-2066762725
// and: https://github.com/GradleUp/nmcp
nmcp {
    val props = project.properties
    centralPortal {
        username = props["centralPortalToken"] as String? ?: ""
        password = props["centralPortalPassword"] as String? ?: ""
        // or if you want to publish automatically
        publishingType = "AUTOMATIC"
    }
}

// see: https://vanniktech.github.io/gradle-maven-publish-plugin/central/#configuring-the-pom
mavenPublishing {
    coordinates("com.jasonernst.kanonproxy", "kanonproxy-client", version.toString())
    pom {
        name = "kanonproxy"
        description = "An anonymous proxy client written in kotlin."
        inceptionYear = "2024"
        url = "https://github.com/compscidr/kanonproxy"
        licenses {
            license {
                name = "GPL-3.0"
                url = "https://www.gnu.org/licenses/gpl-3.0.en.html"
                distribution = "repo"
            }
        }
        developers {
            developer {
                id = "compscidr"
                name = "Jason Ernst"
                url = "https://www.jasonernst.com"
            }
        }
        scm {
            url = "https://github.com/compscidr/kanonproxy"
            connection = "scm:git:git://github.com/compscidr/kanonproxy.git"
            developerConnection = "scm:git:ssh://git@github.com/compscidr/kanonproxy.git"
        }
    }

    signAllPublications()
}