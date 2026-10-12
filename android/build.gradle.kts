allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory = rootProject.layout.buildDirectory.dir("../../build").get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

project(":flutter_local_notifications") {
    tasks.withType<Test>().configureEach {
        onlyIf { false }
    }
}

// 上游 1.2.6 新增：Flutter integration_test 插件会请求 androidx.test:runner:1.2+
// 这类动态版本，动态版本要逐个仓库查询 maven-metadata.xml，
// Maven Central 的 TLS/404 抖动会让整次解析失败（即使 Google Maven 有）。
subprojects {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "androidx.test" && requested.name == "runner") {
                useVersion("1.5.2")
                because("pin past dynamic 1.2+ metadata fetch")
            }
        }
    }
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
