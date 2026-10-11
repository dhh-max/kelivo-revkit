plugins {
    id("com.android.application")
}

android {
    namespace = "zhou.kelivo.bootstrapdemo"
    compileSdk = 36
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "zhou.kelivo.bootstrapdemo.v2"
        minSdk = 23
        targetSdk = 36
        versionCode = 2
        versionName = "2.0.0"

        ndk {
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            cmake {
                abiFilters += "arm64-v8a"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
}
