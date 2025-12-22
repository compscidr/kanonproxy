plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "com.jasonernst.kanonproxy"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.jasonernst.kanonproxy"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "android.support.test.runner.AndroidJUnitRunner"
    }
    buildFeatures {
        compose = true
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        }
    }
    packaging {
        resources {
            pickFirsts.add("logback-test.xml")
            pickFirsts.add("/META-INF/INDEX.LIST")
        }
    }
}

dependencies {
    implementation(project(":core")) {
        exclude("ch.qos.logback")
    }
    implementation(project(":client")) {
        exclude("ch.qos.logback")
    }
    implementation(project(":server")) {
        exclude("ch.qos.logback")
        exclude("com.jasonernst.icmp")
    }
    debugImplementation(libs.compose.ui.tooling.preview)
    runtimeOnly(libs.logback.android)
    implementation(libs.icmp.android)
    implementation(libs.knet)
    implementation(libs.packetdumper)
    implementation(libs.androidx.preference)
    implementation(platform(libs.compose.bom))
    implementation(libs.bundles.compose)
    implementation(libs.material) // required for the themes.xml
    implementation(libs.slf4j.api)
    implementation(libs.compose.ui.tooling)
    implementation(libs.accompanist.permissions)
    testImplementation(libs.junit)
    androidTestImplementation(libs.runner)
    androidTestImplementation(libs.espresso.core)
}