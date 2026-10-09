# Full-Time-Pad (FTP)

**An experimental symmetric stream cipher implemented in C++20.**

Full-Time-Pad is a project where I explored how to build a small symmetric encryption primitive. The implementation combines byte level permutations with ARX operations sufficient diffusion and confusion to pass NIST randomness tests.

This repository contains the C++ implementation as well as the paper behind the design.

## What I worked on

- **Implemented the transformation in C++.** The core code operates on a 256-bit (32-byte) key and uses 32-bit words for ARX operations.
- **Explored permutation based diffusion.** Constant byte permutation tables rearrange key material between transformation steps. The implementation includes endian aware permutation tables and compile time selection of the native byte order.
- **Built multiple algorithm versions.** The `FullTimePad::Version` enum exposes versions 1.0, 1.1, and 2.0, making it possible to compare alternative transformation designs within the same codebase and make the minimal sufficient version to pass select cryptoanalysis tests.
- **Investigated behaviour experimentally.** The accompanying code and write-up explore round-trip correctness, output changes across successive indices, collision-style measurements, and performance comparisons.

## How it works

At a high level, the design combines two kinds of operations:

1. **Permutation:** bytes are rearranged according to predefined tables to mix byte positions across 32-bit words.
2. **ARX transformation:** 32-bit values are manipulated using addition, bitwise rotations, and XOR.

The transform takes input bytes, a 256-bit key, and a 64-bit encryption index. The index is intended to vary the transformation between uses. The implementation has several versions of the core transformation so their behaviour and performance can be explored without maintaining separate codebases.

This is a high level description of the implementation, not a security argument. The design has not undergone the kind of independent cryptanalysis required before a cipher should be trusted with real data.

### Requirements

- g++
- GNU Make

Build the project from the repository root:

```
make
```

Run the example program:

```
./fulltimepad
```

The Makefile enables common compiler warnings and uses optimization flags for the normal build. To build with debug symbols instead:

```
make clean
make debug
```

To remove the generated executable and object files:

```
make clean
```

The example program in `main.cpp` uses a fixed test key and sample input, checks that the transformed output can be transformed back to the original input, and prints outputs for successive encryption indices.

## Repository contents

| File | Purpose |
| --- | --- |
| `fulltimepad.h` | Main class declaration, version selection, permutation tables, and transform interface |
| `fulltimepad.cpp` | Core implementation of the transformations |
| `main.cpp` | Example program for exercising the implementation |
| `makefile` | Build, debug, and documentation targets |
| `FullTimePad.tex` | Old LaTeX source for the technical paper |
| `FullTimePad.pdf` | Old Compiled technical paper |
| `NewFullTimePadPaper.tex` / `NewFullTimePadPaper.pdf` | Newest technical paper |

## Security status and limitations

**Do not use Full-Time-Pad to protect real data.** This is a custom, experimental cipher and has not received sufficient independent cryptanalysis or review to establish that it is secure. Passing round-trip tests, producing outputs that look random, or performing well in a benchmark does not demonstrate resistance to known or future attacks.

In particular:

- The implementation and its design should be treated as experimental.
- The encryption index must be managed correctly by any caller; reusing values may undermine the intended separation between transformations.
- The repository is not a complete, production-ready encryption system with an authenticated-encryption interface, key-management workflow, or protocol design.
- Performance comparisons depend on the exact version, compiler, build flags, hardware, input sizes, and benchmark methodology. Results should be reproduced under controlled conditions before drawing conclusions.

## Why I built it

I wanted my own encryption algorithm.

## License

The source files identify the project as licensed under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. See the license terms that apply to this repository before redistributing or modifying the code.
