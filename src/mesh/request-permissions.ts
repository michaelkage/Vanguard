import { PermissionsAndroid, Platform } from "react-native";
import { VanguardNearby } from "../../modules/vanguard-nearby/src";

export async function requestVanguardNearbyPermissions(): Promise<boolean> {
  if (Platform.OS !== "android") {
    throw new Error("The current nearby transport is Android-only");
  }

  const missing = await VanguardNearby.getMissingPermissions();
  if (missing.length === 0) return true;

  const results = await PermissionsAndroid.requestMultiple(
    missing as Parameters<typeof PermissionsAndroid.requestMultiple>[0]
  );
  return missing.every(permission => results[permission] === PermissionsAndroid.RESULTS.GRANTED);
}
