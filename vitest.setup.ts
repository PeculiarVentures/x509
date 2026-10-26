import "@abraham/reflection";
import { Crypto } from "@peculiar/webcrypto";
import { cryptoProvider } from "./src/index";

// The specs run against @peculiar/webcrypto, which also covers the algorithms only it
// implements (brainpool and K-256 curves, Ed448/X448 as "EdDSA"/"ECDH-ES"). Specs read it
// back with cryptoProvider.get().
cryptoProvider.set(new Crypto());
