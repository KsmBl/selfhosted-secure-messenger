plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.selfhosted.securemessenger"
    compileSdk = 37

    defaultConfig {
        applicationId = "org.selfhosted.securemessenger"
        minSdk = 26
        targetSdk = 37
        // Set by scripts/build-android-apk.sh: versionCode = number of git
        // commits, so every build is newer and Android refuses downgrades.
        versionCode = (findProperty("ssm.versionCode") as String?)?.toInt() ?: 1
        versionName = findProperty("ssm.versionName") as String? ?: "0.1.0"
        // Only ABIs that libssm_ffi is built for (JNA ships more).
        ndk {
            abiFilters += (findProperty("ssm.abis") as String? ?: "arm64-v8a,armeabi-v7a,x86_64").split(",")
        }
    }

    // Release signing from the environment (scripts/build-android-apk.sh --release).
    val keystore = System.getenv("SSM_KEYSTORE")
    if (keystore != null) {
        signingConfigs {
            create("release") {
                storeFile = file(keystore)
                storePassword = System.getenv("SSM_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("SSM_KEY_ALIAS")
                keyPassword = System.getenv("SSM_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // UniFFI bindings load libssm_ffi.so through JNA.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    // Push wake-ups through the user's UnifiedPush distributor (e.g. ntfy).
    implementation("org.unifiedpush.android:connector:3.3.5")
}
