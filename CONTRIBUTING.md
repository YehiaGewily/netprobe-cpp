# Contributing to NetProbe

Thanks for taking a look. NetProbe is a packet capture and analysis tool, which means most of its code reads bytes that came off a hostile network. That shapes what review looks for, so this document is mostly about that rather than about style.

## Building

You need CMake 3.20+, a C++20 compiler, and libpcap (or the Npcap SDK on Windows). All other dependencies are fetched and pinned automatically by CMake.

**Windows** — Visual Studio 2022 with the C++ Desktop workload, the [Npcap driver](https://npcap.com/#download), and the Npcap SDK extracted to `C:\Npcap-SDK`:

```powershell
.\build_project.bat
```

**Linux** — `sudo apt install build-essential cmake libpcap-dev libgl1-mesa-dev libgtk-3-dev pkg-config`

**macOS** — Xcode Command Line Tools and CMake; libpcap and OpenGL ship with the OS.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The build also produces `data/sample.pcap`, a small synthetic capture you can open without any capture privileges — useful for exercising the whole pipeline while developing.

## Running the checks CI runs

Before opening a pull request, run whichever of these your platform supports. CI runs all of them.

**Tests** (all platforms):

```bash
ctest --test-dir build --output-on-failure
```

**Sanitizers** (Clang or GCC):

```bash
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=RelWithDebInfo -DENABLE_SANITIZERS=ON -DBUILD_TESTING=ON
cmake --build build-asan --target NetProbeTests --parallel
ctest --test-dir build-asan --output-on-failure
```

This is the most valuable single check for parser work. A test can pass while reading past the end of a buffer; under ASan it cannot.

**Static analysis** (needs `clang-tidy` and a compile database, so configure with Ninja — the Visual Studio generator does not emit one):

```bash
cmake -S . -B build-tidy -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
find src -name '*.cpp' -print0 | xargs -0 -n1 clang-tidy -p build-tidy --quiet
```

`.clang-tidy` sets `WarningsAsErrors`, so **judge this by the exit code, not by reading the output**. A finding anywhere — including in a header the filter admits — fails the run.

**Fuzzing** (Clang only):

```bash
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Release -DBUILD_FUZZERS=ON -DBUILD_TESTING=OFF
cmake --build build-fuzz --target NetProbeFuzzerSeeds NetProbeParserFuzzer --parallel
./build-fuzz/NetProbeFuzzerSeeds build-fuzz/corpus
./build-fuzz/NetProbeParserFuzzer build-fuzz/corpus -max_total_time=60
```

## What review looks for

Ordinary code review, plus three things specific to this project:

**Never trust a length that came off the wire.** Every offset and length in a packet is attacker-controlled. Check it against the actual buffer before using it, and prefer bailing out to clamping and continuing — a parser that "recovers" from an inconsistent length is a parser that eventually reports a hostname assembled from adjacent memory.

**Degrade visibly, not plausibly.** When a packet cannot be parsed, the right outcome is an empty or clearly-marked field. The dangerous failure is not a crash; it is returning something that looks like a real answer, because it gets shown to the user as fact. Tests in `tests/malformed_test.cpp` pin the expected degraded result for each malformed fixture for exactly this reason.

**Bound anything that holds state across packets.** The TLS and QUIC reassemblers buffer data keyed by values from the network. Every such structure needs a size cap, a count cap, and a timeout, or it is a memory-exhaustion primitive.

## Adding tests

- Unit and integration tests go in `tests/`, using GoogleTest. `tests/PacketBuilders.hpp` has wire-format constructors for synthetic frames; extend it rather than hand-rolling bytes in a test.
- Malformed-input fixtures go in `test::malformed::allCases()` in the same header. They are shared with the fuzz seed generator, so one addition improves both the regression suite and the fuzzing corpus.
- If you fix a bug the fuzzer found, check the reproducing input in as a named fixture. That loop is what keeps fixes from regressing.

## Commit and pull request conventions

- Conventional-commit prefixes: `feat:`, `fix:`, `test:`, `docs:`, `build:`, `ci:`, `refactor:`, `perf:`, `chore:`.
- Explain **why** in the commit body, not just what. The diff already shows what changed; what it cannot show is the reasoning or the alternative you rejected.
- One logical change per commit. Keep a refactor and a behaviour change in separate commits.
- Say what you verified and how. "Tests pass" is less useful than naming the case you checked.

## Good first issues

If you are looking for somewhere to start, these are small, self-contained, and need no architectural context:

- **Add a malformed-packet fixture.** Pick a protocol field NetProbe parses, construct a frame that lies about it, add it to `test::malformed::allCases()` with its expected degraded outcome, and confirm the parser handles it. Each one is a few lines and strengthens both the test suite and the fuzz corpus.
- **Extend service identification.** `ProtocolParser::identifyService` maps hostnames to friendly service names. Adding well-known services is a self-contained change with an obvious test.
- **Add a DNS record type.** `DNSParser` handles A, AAAA, CNAME, PTR, SRV, TXT, and HTTPS/SVCB. Others (MX, NS, CAA) follow the same shape.
- **CLI usability.** The headless CLI is deliberately minimal; small additions like a `--quiet` flag or a summary line format are easy to scope.

Larger items worth discussing in an issue first: additional link-layer types, IPv6 extension-header coverage, and anything touching the QUIC decryption path.

## Reporting bugs

A capture file that reproduces the problem is worth more than any description. If the traffic is sensitive, a synthetic `PacketBuilders.hpp`-style reproduction is just as good. Include your OS, how NetProbe was built, and whether it was running elevated.
