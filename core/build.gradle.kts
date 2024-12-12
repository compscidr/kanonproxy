plugins {
    alias(libs.plugins.jetbrains.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    id("java-library")
    id("jacoco")
    alias(libs.plugins.git.version)
    alias(libs.plugins.sonatype.maven.central)
    alias(libs.plugins.gradleup.nmcp)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

tasks.jacocoTestReport {
    reports {
        xml.required = true
        html.required = true
    }
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

testing {
    suites {
        val test by getting(JvmTestSuite::class) {
            useJUnitJupiter()
        }
    }
}

jacoco {
    toolVersion = "0.8.12"
}

dependencies {
    api(libs.slf4j.api)
    api(libs.knet)
    testImplementation(libs.icmp.linux)
    testImplementation(libs.bundles.test)
    testRuntimeOnly(libs.junit.jupiter.engine)
    testImplementation(libs.logback.classic)
    testImplementation(libs.testservers)
    testImplementation(libs.knet)
    implementation(kotlin("stdlib"))
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
    publishAllPublications {
        username = props["centralPortalToken"] as String? ?: ""
        password = props["centralPortalPassword"] as String? ?: ""
        // or if you want to publish automatically
        publicationType = "AUTOMATIC"
    }
}

// see: https://vanniktech.github.io/gradle-maven-publish-plugin/central/#configuring-the-pom
mavenPublishing {
    coordinates("com.jasonernst.kanonproxy", "kanonproxy", version.toString())
    pom {
        name = "kanonproxy"
        description = "An anonymous proxy written in kotlin."
        inceptionYear = "2024"
        url = "https://github.com/compscidr/kanonproxynet"
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