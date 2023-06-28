# Keyring Program

Program for managing encryption keys.

Goals:

- Store one or more public encryption keys for a particular user in a unique on-chain location protected by their authority
- Support additional configurations required for a particular encryption algorithm key
- Allow a user to add or remove keys from their on-chain keystore
- Allow for future support of new encryption algorithms with this program being **frozen**
- Establish a workflow (through sRFC-like process) to add support/recognition for new encryption algorithms

## Storing Encryption Keys

This program is designed to manage encryption public keys for various Solana wallets.

The Keyring Program leverages an account (PDA) dubbed a "Keystore" that houses all publicly available encryption public keys that the particular wallet owns and has made available in their keystore.

A user's keystore is mapped to their wallet address with the following Program-Derived Address seed pattern:

```shell
"keystore" + < wallet address >
```

## Supporting Additional Configurations

The data of a `KeystoreEntry` is structured in a **nested TLV structure**, which allows us to dynamically manage various types of keys and configs. ([see below section](#supporting-dynamic-encryption-algorithms))

A particular encryption algorithm may require some additional configurations or parameters to perform encryption/decryption. These can be specified in the `(Additional configurations)` section in the structure layout below.

The nested TLV structure is formatted as follows:

```text
* T: The new entry discriminator (marks the start of a new keystore entry)
* L: The length of the entry
* V: The data of the entry
    * (Encryption key)
        * T: The algorithm discriminator (provided by sRFC workflow)
        * L: The length of the key
        * V: The key itself
    * (Additional configurations)
        * T: The configuration discriminator (marks additional
          configurations are present)
        * L: The total length of the configuration data
        * V: The configuration data
            * (Configuration: `K, V`)
                * T: The configuration key (provided by sRFC workflow)
                * L: The configuration value length
                * T: The configuration value
```

As you can see, within each entry we have a **key** and a **configuration**. The discriminator for the key will dictate the key's encrpyion algorithm and qsubsequently it's length in bytes, while the discriminator for configurations will be akin to a `boolean` or `Option`. In psuedo-code:

```text
Has configs:            [<config discriminator>] [<length>] [<data>] 
Does not have configs:  [<no config discriminator>]     -- no data
```

## Adding & Removing Keys

A key and its associated configurations can only be written to or removed from a particular keystore account if the authority has signed the transaction.

An authority must provide the **entire buffer of data** in order to successfully add or delete a key. When deleting, the program will match against the entire buffer that defines the key **and associated configurations**.

## Supporting Dynamic Encryption Algorithms

Typically a Solana program has well-defined state within its source code and one can use that source code to infer the exact byte-wise representation of the program's managed account data. However, this program actually cedes that state management over to it's tightly-coupled client.

More specifically, in order to ensure we can seamlessly add support for more encryption algorithms and their corresponding required configurations, the program-client relationship is designed as follows:

- The program simply writes bytes to the keystore accounts, with _some_ guardrails on pre-defined discriminators
  - For example, the program will ensure you have the proper TLV discriminators present to:
    - Define a new keystore entry
    - Define additional configurations for a key
- The client introduces new discriminators and actually holds the source code for deserializing keystore entries from an on-chain account
  - This allows us to use an sRFC workflow to agree on the byte-wise structure of a new encryption algorithm **without introducing breaking changes to the code**

## Establishing an sRFC-Like Workflow

Along with this program we must establish a workflow for adding new encryption algorithms to the supported collection within the program's client(s).

A simple solution is to merely use GitHub Pull Requests directly into the client code itself, as the code has been written succinctly enough for these PRs to be straightforward to author.

When seeking to introduce support for a new encryption algorithm in the Keyring Program, one should submit a Pull Request with:

- An overview of this encryption algorithm and links to resources where community members can read more
- Some use cases on Solana where support for this algorithm is paramount
- A unique 8-byte discriminator for the encryption algorithm (the key discriminator)
- If configurations are required to use this encryption algorithm: An explicit data structure outlining all required configurations

⚠️ Note: I would like to make this something like a publicly-hosted JSON that we can change without having to push any code changes, on- or off-chain.
