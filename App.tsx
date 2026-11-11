import { StatusBar } from "expo-status-bar";
import { SafeAreaView, StyleSheet, Text, View } from "react-native";

export default function App() {
  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar style="light" />
      <View style={styles.container}>
        <Text style={styles.eyebrow}>LOCAL-FIRST CAMPUS NETWORK</Text>
        <Text style={styles.title}>Vanguard</Text>
        <Text style={styles.description}>
          Identity and communication designed to keep working when the internet does not.
        </Text>
        <View style={styles.status}>
          <View style={styles.statusDot} />
          <Text style={styles.statusText}>Client foundation initialized</Text>
        </View>
        <Text style={styles.note}>
          No identity enrollment, peer discovery, or network transfer is enabled in this build.
        </Text>
      </View>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: "#101820" },
  container: { flex: 1, justifyContent: "center", paddingHorizontal: 28 },
  eyebrow: {
    color: "#80CBC4", fontSize: 11, fontWeight: "700",
    letterSpacing: 2.2, marginBottom: 14
  },
  title: { color: "#F4F7FA", fontSize: 48, fontWeight: "800", letterSpacing: -1.8 },
  description: {
    color: "#B7C3CC", fontSize: 17, lineHeight: 26,
    marginTop: 12, maxWidth: 420
  },
  status: {
    alignItems: "center", alignSelf: "flex-start", backgroundColor: "#1B2A32",
    borderRadius: 24, flexDirection: "row", marginTop: 36,
    paddingHorizontal: 14, paddingVertical: 10
  },
  statusDot: {
    backgroundColor: "#80CBC4", borderRadius: 5, height: 8,
    marginRight: 9, width: 8
  },
  statusText: { color: "#D9E5E8", fontSize: 13, fontWeight: "600" },
  note: { color: "#81919B", fontSize: 12, lineHeight: 18, marginTop: 20, maxWidth: 360 }
});
