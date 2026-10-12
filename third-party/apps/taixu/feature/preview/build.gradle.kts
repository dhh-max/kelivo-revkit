plugins {
    alias(libs.plugins.taixu.android.feature)
}

android {
    namespace = "top.wkbin.taixu.feature.preview"
}

dependencies {
    implementation(project(":feature:theme"))
    implementation(libs.androidx.activity.compose)
    implementation(libs.backdrop)
}
