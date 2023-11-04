# Wallet Companion Program

This sRFC is to discuss a solution to [sRFC 00007](https://forum.solana.com/t/srfc-00007-encryption-standard-for-solana-keypairs/65) that we believe might serve other vaulable use cases for wallets on Solana.

## Keyring

The [Keyring program](https://github.com/buffalojoec/keyring-program) is a spec implementation of a program designed to store encrpytion key configurations, as described in [sRFC 00007](https://forum.solana.com/t/srfc-00007-encryption-standard-for-solana-keypairs/65).

Keyring is designed to be a flexible **frozen program**, where changes introduced to the protocol occur on the client side.

This is implemented as follows:

- Program-Side:
  - The seeds to derive the Keyring PDA account are hard-coded (ie. `"keyring" + <wallet address>`).
    - <https://github.com/buffalojoec/keyring-program/blob/main/program/src/state.rs#L9>
  - Processor merely writes arbitrary bytes to the Keyring PDA account owned by the user at the user's direction.
    - <https://github.com/buffalojoec/keyring-program/blob/main/program/src/processor.rs#L56-L79>
- Client-Side:
  - Serialization of encryption algorithm key configs are defined here, using an interface-based approach.
    - <https://github.com/buffalojoec/keyring-program/blob/main/client/src/keystore.rs>
  - Changes to supported encryption algorithms would be merged to the client code.

**Flaws:**

- Keyring is bound to one supported PDA account per user, and this could not be changed with a frozen program.
- Anyone can fill their Keyring PDA account with any arbitrary bytes up to the maximum account size, and forgo the proper format for an encryption key configuration as defined by the Keyring client(s).
  - It's believed that this would only affect that one particular user, since they would be corrupting only their key storage and no one else's.
  - However, this introduces a potential problem with forcing wallets to load a massive account size, which could be problematic.

## Expanding on Keyring

In discussions about how Keyring would potentially be used by wallets _or_ individual users (sending their own instructions to Keyring), we recognized the potential for other use cases of a similar program to Keyring.

Namely, [sRFC 00009](https://forum.solana.com/t/srfc-00009-sign-in-with-programmable-smart-wallets-using-off-chain-delegates/104) brought this to our attention.

### Supporting More Than Keystores

One approach would be to move the PDA seeds out of the program and into the client, allowing the client to determine which PDA account this arbitrary data is to be stored within.

Then, this program would be more than just a keystore, and could also store other kinds of data, which can be grouped on the appropriate PDA account. For example, you could have `"keyring" + <walet address>` be the PDA that stores encryption key configurations, while `"domains" + <wallet address>` could be the PDA that stores a user's owned domains like `joe.sol`.

Changes could then be made to the client to introduce new supported data standards by the program, which could be dubbed something like "Wallet Companion Program" instead of specifically "Keyring".

This would result in the following implementation:

- Program-Side:
  - Processor merely writes arbitrary bytes to the directed PDA account owned by the user at the user's direction.
- Client-Side:
  - The seeds to derive the Keyring PDA account are fed to the program (ie. `"my-data" + <wallet address>`).
  - Serialization of _any_ supported data standards are defined here, using an interface-based approach.
  - Changes to _any_ supported data standards would be merged to the client code.

**Flaws:**

- Namespace collisions
  - Any user could push arbitrary bytes to an account at some namespace (ie. `"namespace" + <wallet address>`), resulting in the inability to add the proper data to this account in the future.
    - Like Flaw #2 listed under **Keyring**, this would only affect the user's own data and no one else's.
  - One wallet could choose to use a namespace for something, while other wallets may not.
    - This means we would need some kind of agreed upon namespace standard across all wallet participants.
- Large data loading problem is expanded to more than one PDA
  - Like Flaw #2 listed under **Keyring**, any PDA account could be filled with large arbitrary data and cause problems with forcing wallets to load this data. This problem would now be expanded to all namespaces.

### Supporting More Than Keystores, But On-Chain

An alternative approach to the above section is to simply make these changes to the on-chain program itself, and forgo freezing the program altogether.

The implementation could be as follows:

- Program-Side:
  - The seeds to derive the Keyring PDA account are stored in the program (ie. `"my-data" + <wallet address>`).
  - Processor serializes specifically-formatted bytes to the directed PDA account owned by the user at the user's direction.
  - Serialization of _any_ supported data standards are defined here, using an interface-based approach.
  - Changes to _any_ supported data standards would be merged to the program code.
- Client-Side:
  - Mimicked serialization formats of _any_ supported data from the program's implementation.

**Flaws:**

- Program would not be frozen
  - This would mean changes would have to be introduced to the program code, a new crate published, and a new program deployed.
  - Client code would also have to update in order to match the on-chain program's code (serialization formats).
  - This could be problematic for wallets if the program changes periodicially.

## Questions

Ultimately the main question is:

- Do wallets have a need for a more expanded data program for various use cases of user data, or is a simple keystore enough?
  - If so, how should we handle dynamic data serialization formats?
    - If it's all handled off-chain, how do we protect against abuse or attacks?
    - If it's all handled off-chain, how do we preserve namespaces?
  - If not, will there come a need in the future for a similar program for something else?
- Should this program be frozen?
