import { requireNativeModule } from "expo-modules-core";

export interface VanguardDeviceIdentity {
  readonly algorithm: "Ed25519";
  /** Base64url-encoded X.509 SubjectPublicKeyInfo bytes. */
  readonly publicKey: string;
  readonly keyProtection: "android-keystore-wrapped";
}

interface NativeVanguardIdentity {
  getOrCreateIdentity(): Promise<VanguardDeviceIdentity>;
  sign(message: string): Promise<string>;
  verify(publicKey: string, message: string, signature: string): Promise<boolean>;
  deleteIdentity(): Promise<boolean>;
}

const NativeIdentity = requireNativeModule<NativeVanguardIdentity>("VanguardIdentity");

export const VanguardIdentity = {
  getOrCreate: (): Promise<VanguardDeviceIdentity> => NativeIdentity.getOrCreateIdentity(),
  sign: (canonicalMessage: string): Promise<string> => NativeIdentity.sign(canonicalMessage),
  verify: (
    publicKey: string,
    canonicalMessage: string,
    signature: string
  ): Promise<boolean> => NativeIdentity.verify(publicKey, canonicalMessage, signature),
  delete: (): Promise<boolean> => NativeIdentity.deleteIdentity()
};
