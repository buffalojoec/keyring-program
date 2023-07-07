import {
  Connection,
  Keypair,
  PublicKey,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

/**
 * Builds a transaction using the V0 format
 * @param connection Connection to Solana RPC
 * @param instructions Instructions to send
 * @param payer Transaction Fee Payer
 * @param signers All required signers, in order
 * @returns The transaction v0
 */
export async function buildTransactionV0(
  connection: Connection,
  instructions: TransactionInstruction[],
  payer: PublicKey,
  signers: Keypair[],
): Promise<VersionedTransaction> {
  let blockhash = await connection
    .getLatestBlockhash()
    .then((res) => res.blockhash);
  const messageV0 = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: blockhash,
    instructions,
  }).compileToV0Message();
  const tx = new VersionedTransaction(messageV0);
  signers.forEach((s) => tx.sign([s]));
  return tx;
}
