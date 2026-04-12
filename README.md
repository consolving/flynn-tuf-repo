# Flynn TUF Repository

This repository hosts the TUF (The Update Framework) metadata and components for Flynn.

This project is dedicated to restoring the Flynn ecosystem. We would like to acknowledge the awesome work that was done by the [flynn.io team](https://github.com/flynn) in building the original platform.

## Usage

This repository is used by the Flynn builder and host components to securely verify and download updates.

## Contents

- `root.json`, `targets.json`, `snapshot.json`, `timestamp.json`: TUF metadata files.
- `targets/`: Directory containing signed component binaries and assets.
