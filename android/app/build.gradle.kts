plugins {
    id("com.android.application")
}

// APK 内加载的站点地址：优先 -PappUrl=，其次环境变量 APP_URL，最后占位地址。
val appUrl: String = (findProperty("appUrl") as String?)
    ?: System.getenv("APP_URL")
    ?: "https://example.com"

val appVersionCode: Int = (findProperty("versionCode") as String?)?.toIntOrNull() ?: 1
val appVersionName: String = (findProperty("versionName") as String?) ?: "1.0.0"
val appUrlLiteral: String = appUrl.replace("\\", "\\\\").replace("\"", "\\\"")

android {
    namespace = "com.doremy.floatphone"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.doremy.floatphone"
        minSdk = 26
        targetSdk = 35
        versionCode = appVersionCode
        versionName = appVersionName

        buildConfigField("String", "APP_URL", "\"$appUrlLiteral\"")
    }

    // 只有当四个签名环境变量都存在、且密钥文件已就位时才创建 release 签名配置。
    // 本地没有密钥时仍可构建（回退 debug 签名），方便调试。
    val storePasswordValue = System.getenv("SHELLKEYSTOREPASSWORD")
    val keyAliasValue = System.getenv("SHELLKEYALIAS")
    val keyPasswordValue = System.getenv("SHELLKEYPASSWORD")
    val keystoreFile = file("release.jks")
    val hasSigning = !storePasswordValue.isNullOrBlank() &&
        !keyAliasValue.isNullOrBlank() &&
        !keyPasswordValue.isNullOrBlank() &&
        keystoreFile.exists()

    signingConfigs {
        if (hasSigning) {
            create("release") {
                storeFile = keystoreFile
                storePassword = storePasswordValue
                keyAlias = keyAliasValue
                keyPassword = keyPasswordValue
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
