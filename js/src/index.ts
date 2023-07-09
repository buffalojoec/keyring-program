export * from "./algorithm";
export * from "./instruction";
export * from "./state";
export * from "./tlv";
export * from "./util";

import { PublicKey } from "@solana/web3.js";

/**
 * The Keyring Program ID
 */
export const PROGRAM_ID: PublicKey = new PublicKey(
  "8FSgMvQXodCVyd2fbFhTsEDz3DrMK4aXcyUME3Yeuhc3",
);
