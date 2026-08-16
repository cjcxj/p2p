plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.p2pdemo"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.example.p2pdemo"
        minSdk = 24
        targetSdk = 36
        versionCode = 18
        versionName = "2.9"
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
}

dependencies {
    implementation(files("libs/p2p.aar"))
}
