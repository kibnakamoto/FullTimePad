# Full-Time-Pad (FTP)

**A C++20 experiment in symmetric-key stream generation, byte-level permutations, and ARX-style state transformations.**

Full-Time-Pad began as an attempt to design my own encryption primitive and understand the trade-offs that appear when a cryptographic construction moves from a mathematical description to real C++ code. The repository contains several generations of the transformation, a working implementation, and technical papers documenting the design experiments and analysis.

One of the most interesting parts of the project is the gap between the paper's general construction and the final implementation. The paper describes the underlying permutation and-word transformation approach. The optimized C++ implementation specializes that idea into a different execution schedule, with the most recent version structured around a smaller number of permutation passes and explicitly maintained 32-bit state.

## Implementation highlights

- **Low-level 256-bit state handling.** The transformation works on a 32-byte key state, reinterpreted as eight 32-bit words for arithmetic and bitwise operations. The implementation explicitly accounts for host endianness and provides corresponding compile time permutation tables.
- **A custom permutation/word-mixing construction.** Byte LUT tables move bytes between positions in the state, while word level computation combines overflowing  addition, XOR, and left/right bit rotations. The version 2.0 path also uses multiplication in its state-update schedule.
- **Multiple transformation schedules in one codebase.** `FullTimePad::Version` exposes versions 1.0, 1.1, and 2.0. Compile time template selection keeps version-specific code paths distinct and makes the alternatives straightforward to compare without maintaining separate implementations.
- **An implementation substantially different from the paper's presentation.**  The software doesn't translate the paper's original loop. It uses a optimized schedule benefiting from minimizing memory read/write communication and unrolled loop as well as parallel byte swapping.
- **Performance-focused iteration.** The implementation was optimized to achieve an **11x speedup over pseudo-code equivelant implementation**. The main goal was to reduce cost of transformation by not only by mathematical operations, but also by how the state is represented, how often data are rearranged and used, and how the compiler can optimize the update schedule. The exact speedup depends on the device used and its optimizations, most optimizations used in the fulltimepad.cpp implemntation is implicit but explicitly hinted at the compiler (e.g. 4 lines of permutations back to back is for parallel computation only because the compiler is smart).
- **Not all software tests are preserved** Most tests utilizing SIMD instruction sets explicitly are discarded due to the originally private nature of the research paper.

## How the transformation is used

The implementation derives a 32-byte output from a 32-byte input key and a 64-bit encryption index. That output is then XORed with the input data. For data longer than 32 bytes, the implementation generates successive blocks using incrementing index values (Maximum data per encryption key is 512 Exbibytes).

At the transformation level, the design has two interacting parts:

1. **Byte-position permutation.** A predefined table specifies how the 32 bytes are rearranged. Separate table layouts account for little-endian and big-endian hosts, and the active layout is selected at compile time.
2. **Word level state updates.** The same 32-byte state is viewed as eight 32-bit words. The transformation updates those words using arithmetic, rotations, and XOR, mixing the index and fixed constants into the evolving state. Essentially benefiting from reinterpret\_cast/unions in C/C++ for cryptographic benefits.

The encryption index is part of the transformation input only for the purpose of encrypting multiple blocks of data using the same key. A caller must manage it correctly and avoid reusing an index in contexts where distinct keystream output is required. The example program exercises successive indices and checks that applying the same transformation again recovers the original input. Otherwise, the same vulnerability in One-Time-Pad key reuse persists here. Refer to OneTimePad repository for more information on the cryptoanalysis behind it.

## Performance

The implementation reached an **11x speedup compared with psuedo-code equivelant implementation** during development.

The repository's papers also discuss comparisons with established primitives. Those historical results should be read with their stated assumptions in mind: output sizes, implementation maturity, and benchmark methodology can materially affect the result. The 11x figure refers to optimization within this project, not a general claim of superiority over ChaCha20, AES, or other production ciphers.

## Build and run

### Requirements

- g++
- GNU Make

Build from the repository root:

```
make
```

Run the example:

```
./fulltimepad
```

```
make clean
make debug
```

Remove the executable and object files:

```
make clean
```

The example in `main.cpp` uses a fixed test key and a 32-byte input. It applies version 2.0 at successive encryption indices, prints the generated outputs, and checks that applying the same indexed transformation again restores the original input.

## Repository layout

| File | Description |
| --- | --- |
| `fulltimepad.h` | Public class interface, version enum, state and permutation declarations, and transformation API |
| `fulltimepad.cpp` | Transformation implementations, endian-aware byte/word handling, permutation logic, and version-specific schedules |
| `main.cpp` | Example driver for round-trip checks and successive-index output |
| `makefile` | Optimized and debug build targets, plus paper-related targets |
| `FullTimePad.tex` / `FullTimePad.pdf` | Earlier technical paper and compiled version |
| `NewFullTimePadPaper.tex` / `NewFullTimePadPaper.pdf` | Latest paper I wrote |

## Design notes and security status

This is a custom cryptographic construction intended for experimentation and implementation study. It is **not suitable for protecting real data (probably not)**. The code and accompanying experiments explore output behaviour, statistical tests, and performance, but these do not establish cryptographic security. Statistical randomness tests in particular cannot rule out exploitability.

The implementation should be considered alongside several important limitations:

- The construction has not received the level of independent cryptanalysis and review expected of a trusted cipher.
- The caller is responsible for correct encryption-index management; index reuse can undermine the intended separation between generated keystream blocks.
- This repository is not a complete authenticated-encryption system. It does not provide an established AEAD interface, an application-level nonce protocol, or a production key-management workflow.
- The paper describes the design rationale and earlier construction in more detail, but it is not a line-by-line specification of every optimization in the C++ version. For exact behaviour, the implementation is authoritative.

## Why I built it

I wanted my own encryption algorithm.

## License

The source files identify the project as licensed under **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**. Consult the repository's license terms before redistributing or modifying the code.
