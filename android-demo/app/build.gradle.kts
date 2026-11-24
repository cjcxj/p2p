plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.example.p2pdemo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.p2pdemo"
        minSdk = 24
        targetSdk = 36
        versionCode = 19
        versionName = "3.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
}

// Every version here is pinned to what this machine's Gradle cache actually
// holds, so `gradle --offline` can build without a download. material-ripple and
// material-icons-core are listed because Material3 would otherwise ask for
// versions that were never fetched.
dependencies {
    implementation(files("libs/p2p.aar"))

    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.compose.ui:ui:1.9.0")
    implementation("androidx.compose.foundation:foundation:1.9.0")
    implementation("androidx.compose.material3:material3:1.3.2")
    implementation("androidx.compose.material:material-ripple:1.9.0")
    implementation("androidx.compose.material:material-icons-core:1.7.8")

    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.0")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
