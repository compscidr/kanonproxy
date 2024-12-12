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
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    jvmToolchain(21)
}

jacoco {
    toolVersion = "0.8.12"
}

dependencies {
    implementation(project(":core"))
    implementation(libs.knet)
    implementation(libs.icmp.linux)
    runtimeOnly(libs.logback.classic)
}

/ see: https://github.com/vanniktech/gradle-maven-publish-plugin/issues/747#issuecomment-2066762725
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
    coordinates("com.jasonernst.kanonproxy", "kanonproxy-server", version.toString())
    pom {
        name = "kanonproxy"
        description = "An anonymous proxy server written in kotlin."
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