plugins {
    id("java")
    id("org.jetbrains.intellij") version "1.17.2"
}

group = "dev.piilex"
version = "0.1.0"

repositories {
    mavenCentral()
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

intellij {
    version.set("2024.1")
    type.set("IC") // IntelliJ Community
    plugins.set(listOf(
        // Languages for file type support
        "com.intellij.java",
        "org.jetbrains.kotlin",
        "PythonCore:241.14494.150",
        "org.jetbrains.plugins.go:241.14494.150",
        "com.intellij.css" // needed for some platform deps
    ))
}

tasks {
    patchPluginXml {
        sinceBuild.set("241")
        untilBuild.set("243.*")
        changeNotes.set("""
            <h3>0.1.0</h3>
            <ul>
                <li>Initial release</li>
                <li>Real-time PII detection via LSP</li>
                <li>50+ PII types across 6 languages</li>
                <li>Data flow analysis warnings</li>
                <li>Quick fix code actions</li>
            </ul>
        """.trimIndent())
    }

    signPlugin {
        certificateChain.set(System.getenv("CERTIFICATE_CHAIN"))
        privateKey.set(System.getenv("PRIVATE_KEY"))
        password.set(System.getenv("PRIVATE_KEY_PASSWORD"))
    }

    publishPlugin {
        token.set(System.getenv("PUBLISH_TOKEN"))
    }
}
