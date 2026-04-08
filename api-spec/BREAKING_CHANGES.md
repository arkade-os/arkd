# API Breaking Changes and Best Practices

This document outlines the policies and best practices for evolving the Ark API (Protobuf and OpenAPI) to ensure stability and backward compatibility for clients.

## ⚠️ Important Note on Stability

`arkd` is currently in **Alpha**. While we strive for stability, the API may undergo breaking changes as the protocol matures. This document serves as the guide for how we manage those changes.

## What Constitutes a Breaking Change?

We use [`buf`](https://buf.build/) to automatically detect breaking changes in our Protobuf definitions. The following are considered breaking:

- **Deleting a field**: Removing a field from a message.
- **Changing a field tag number**: Changing the assigned number (e.g., `string name = 1;` to `string name = 2;`).
- **Changing a field type**: For example, changing `int32` to `string`.
- **Changing a field name**: While binary-compatible, this breaks generated code in most languages.
- **Changing field labels**: For example, changing a field from optional to `repeated`.
- **Deleting or renaming** a message, enum, service, or method.

## How to Resolve Breaking Changes

If breaking changes are detected by the automated check (`./scripts/check-proto-breaking`), use the following framework to resolve them:

1. **Revert the breaking changes**: If the change was accidental or can be avoided, revert it to maintain compatibility.
2. **Add new fields**: Instead of modifying existing fields, add new ones with a **new tag number** (the number after the `=`). Use the `[deprecated = true]` option for the old field. This is the preferred way to evolve the API without breaking existing clients.
   ```proto
   // Bad: Changing type or name on the same tag number (1)
   // int32 amount = 1;

   // Good: Keep tag 1 as is, and add tag 2 for the new field
   int32 amount = 1 [deprecated = true];
   string amount_v2 = 2;
   ```
3. **Use field reservations**: If you must delete a field, reserve its tag number and name in the message to prevent future reuse. Note that deleting a field is still a breaking change and should only be done when a break is acceptable.
   ```proto
   message MyMessage {
     reserved 4, 5 to 10;
     reserved "old_field";
   }
   ```
4. **Document intentional changes**: If a breaking change is strictly necessary (e.g., for security or fundamental protocol fixes), clearly document the rationale in your Pull Request and coordinate with known client maintainers.

## Verification Tooling

### Automated Check
We use a script to check for breaking changes against the `master` branch. This script is integrated into our GitHub Actions:
```sh
./scripts/check-proto-breaking master
```
