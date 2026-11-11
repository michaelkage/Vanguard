import type { ExpoConfig } from "expo/config";

const config: ExpoConfig = {
  name: "Vanguard",
  slug: "vanguard",
  scheme: "vanguard",
  version: "0.1.0",
  orientation: "portrait",
  userInterfaceStyle: "automatic",
  newArchEnabled: true,
  ios: {
    bundleIdentifier: "dev.vanguard.app",
    supportsTablet: true,
    config: { usesNonExemptEncryption: false }
  },
  android: {
    package: "dev.vanguard.app",
    adaptiveIcon: { backgroundColor: "#101820" }
  },
  plugins: [
    ["expo-sqlite", { useSQLCipher: true }],
    ["expo-secure-store", {
      configureAndroidBackup: true,
      faceIDPermission: "Allow Vanguard to protect your local encryption key."
    }],
    "expo-dev-client"
  ]
};

export default config;
