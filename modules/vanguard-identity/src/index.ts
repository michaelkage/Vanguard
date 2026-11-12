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
  signBytes(messageBase64Url: string): Promise<string>;
  verify(publicKey: string, message: string, signature: string): Promise<boolean>;
  verifyBytes(publicKey: string, messageBase64Url: string, signature: string): Promise<boolean>;
  deleteIdentity(): Promise<boolean>;
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const MAX_SIGNING_MESSAGE_BYTES = 64 * 1024;

/** Encodes opaque bytes without interpreting them as text. */
function encodeBase64Url(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new TypeError("Vanguard signing input must be a Uint8Array");
  }
  if (bytes.byteLength > MAX_SIGNING_MESSAGE_BYTES) {
    throw new RangeError("Vanguard signing input exceeds 64 KiB");
  }

  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const remaining = bytes.length - offset;
    const first = bytes[offset]!;
    const second = remaining > 1 ? bytes[offset + 1]! : 0;
    const third = remaining > 2 ? bytes[offset + 2]! : 0;
    encoded += BASE64URL_ALPHABET[first >>> 2];
    encoded += BASE64URL_ALPHABET[((first & 0x03) << 4) | (second >>> 4)];
    if (remaining > 1) {
      encoded += BASE64URL_ALPHABET[((second & 0x0f) << 2) | (third >>> 6)];
    }
    if (remaining > 2) {
      encoded += BASE64URL_ALPHABET[third & 0x3f];
    }
  }
  return encoded;
}

const NativeIdentity = requireNativeModule<NativeVanguardIdentity>("VanguardIdentity");

export const VanguardIdentity = {
  getOrCreate: (): Promise<VanguardDeviceIdentity> => NativeIdentity.getOrCreateIdentity(),
  sign: (canonicalMessage: string): Promise<string> => NativeIdentity.sign(canonicalMessage),
  /** Signs exact binary input (for example, a protocol transcript) without UTF-8 conversion. */
  signBytes: (message: Uint8Array): Promise<string> =>
    NativeIdentity.signBytes(encodeBase64Url(message)),
  verify: (
    publicKey: string,
    canonicalMessage: string,
    signature: string
  ): Promise<boolean> => NativeIdentity.verify(publicKey, canonicalMessage, signature),
  /** Verifies exact binary input without UTF-8 conversion. */
  verifyBytes: (
    publicKey: string,
    message: Uint8Array,
    signature: string
  ): Promise<boolean> =>
    NativeIdentity.verifyBytes(publicKey, encodeBase64Url(message), signature),
  delete: (): Promise<boolean> => NativeIdentity.deleteIdentity()
};
