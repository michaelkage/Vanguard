plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
}

sourceSets {
    test {
        resources.srcDir(rootProject.file("protocol/test-vectors"))
    }
}

dependencies {
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("org.json:json:20250517")
    testImplementation("org.bouncycastle:bcprov-jdk18on:1.84")
}

tasks.test {
    useJUnitPlatform()
}
