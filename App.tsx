import { StatusBar } from "expo-status-bar";
import { useState } from "react";
import { ActivityIndicator, Pressable, SafeAreaView, StyleSheet, Text, View } from "react-native";
import { VanguardIdentity, type VanguardDeviceIdentity } from "./modules/vanguard-identity/src";

export default function App() {
  const [identity, setIdentity] = useState<VanguardDeviceIdentity | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function createOrLoadIdentity() {
    setBusy(true);
    setError(null);
    try {
      setIdentity(await VanguardIdentity.getOrCreate());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to initialize device identity");
    } finally {
      setBusy(false);
    }
  }

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar style="light" />
      <View style={styles.container}>
        <Text style={styles.eyebrow}>LOCAL-FIRST CAMPUS NETWORK</Text>
        <Text style={styles.title}>Vanguard</Text>
        <Text style={styles.description}>
          Identity and communication designed to keep working when the internet does not.
        </Text>

        <View style={styles.section}>
          <Text style={styles.sectionTitle}>DEVICE IDENTITY</Text>
          {identity ? (
            <>
              <View style={styles.status}>
                <View style={styles.statusDot} />
                <Text style={styles.statusText}>Ed25519 identity initialized</Text>
              </View>
              <Text style={styles.keyLabel}>PUBLIC KEY · BASE64URL</Text>
              <Text selectable style={styles.publicKey}>{identity.publicKey}</Text>
              <Text style={styles.note}>
                Private-key material stays in the native Android layer and is encrypted at rest
                with an Android Keystore-managed AES key. It is not hardware-attested.
              </Text>
            </>
          ) : (
            <>
              <Text style={styles.note}>
                Create a device signing identity. This does not enroll an account or prove campus
                membership.
              </Text>
              <Pressable
                accessibilityRole="button"
                disabled={busy}
                onPress={createOrLoadIdentity}
                style={({ pressed }) => [
                  styles.button,
                  pressed && styles.buttonPressed,
                  busy && styles.buttonDisabled
                ]}
              >
                {busy ? (
                  <ActivityIndicator color="#101820" />
                ) : (
                  <Text style={styles.buttonText}>Create device identity</Text>
                )}
              </Pressable>
            </>
          )}
          {error ? <Text accessibilityRole="alert" style={styles.error}>{error}</Text> : null}
        </View>

        <Text style={styles.footer}>
          Peer discovery, account enrollment, and cloud sync are not enabled in this build.
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: "#101820" },
  container: { flex: 1, justifyContent: "center", paddingHorizontal: 28 },
  eyebrow: { color: "#80CBC4", fontSize: 11, fontWeight: "700", letterSpacing: 2.2, marginBottom: 14 },
  title: { color: "#F4F7FA", fontSize: 48, fontWeight: "800", letterSpacing: -1.8 },
  description: { color: "#B7C3CC", fontSize: 17, lineHeight: 26, marginTop: 12, maxWidth: 420 },
  section: { backgroundColor: "#17242D", borderColor: "#2A3B45", borderRadius: 18, borderWidth: 1, marginTop: 36, padding: 18 },
  sectionTitle: { color: "#80CBC4", fontSize: 11, fontWeight: "800", letterSpacing: 1.8 },
  status: { alignItems: "center", flexDirection: "row", marginTop: 16 },
  statusDot: { backgroundColor: "#80CBC4", borderRadius: 5, height: 8, marginRight: 9, width: 8 },
  statusText: { color: "#D9E5E8", fontSize: 13, fontWeight: "600" },
  keyLabel: { color: "#81919B", fontSize: 10, fontWeight: "700", letterSpacing: 1.2, marginTop: 20 },
  publicKey: { color: "#F4F7FA", fontSize: 12, lineHeight: 19, marginTop: 7 },
  note: { color: "#9BAAB3", fontSize: 12, lineHeight: 19, marginTop: 14 },
  button: { alignItems: "center", alignSelf: "flex-start", backgroundColor: "#80CBC4", borderRadius: 10, marginTop: 20, minHeight: 44, justifyContent: "center", paddingHorizontal: 16 },
  buttonPressed: { opacity: 0.82 },
  buttonDisabled: { opacity: 0.6 },
  buttonText: { color: "#101820", fontSize: 13, fontWeight: "800" },
  error: { color: "#FF8A80", fontSize: 12, lineHeight: 18, marginTop: 12 },
  footer: { color: "#81919B", fontSize: 12, lineHeight: 18, marginTop: 20, maxWidth: 380 }
});
