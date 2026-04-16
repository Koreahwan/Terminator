# Security Papers Index

**Source**: `~/tools/paper_collection/` (814 papers, organized by category)
**Updated**: 2026-02-24
**Purpose**: Quick reference index for offensive security research, CTF, and bug bounty contexts

---

## Top 20 Must-Read Papers (Practical Impact)

1. **2023 - Dissecting American Fuzzy Lop: A FuzzBench Evaluation** — AFL internals (corpus culling, hitcount precision)
2. **2022 - DARWIN: Survival of the Fittest Fuzzing Mutators** — Mutation scheduling + evolution strategy
3. **2020 - Symbolic execution with SymCC: Don't interpret, compile!** — Compile-time symbolic execution (no interpreter overhead)
4. **2020 - WEIZZ: Automatic Grey-Box Fuzzing for Structured Binary Formats** — Grammar-based fuzzing for binary formats
5. **2020 - AFL++: Combining Incremental Steps of Fuzzing Research** — Community fuzzer with 20+ enhancements
6. **2019 - REDQUEEN: Fuzzing with Input-to-State Correspondence** — Discover magic bytes via taint analysis
7. **2020 - ParmeSan: Sanitizer-guided Greybox Fuzzing** — Leverage sanitizer feedback for fuzzing
8. **2020 - GREYONE: Data Flow Sensitive Fuzzing** — DFG-based seed scheduling
9. **2016 - Driller: Augmenting Fuzzing Through Selective Symbolic Execution** — Hybrid fuzzing (AFL + angr)
10. **2022 - LibAFL: A Framework to Build Modular and Reusable Fuzzers** — Composable fuzzer framework
11. **2019 - MOpt: Optimized Mutation Scheduling for Fuzzers** — Particle swarm + fuzzer scheduling
12. **2020 - Magma: A Ground-Truth Fuzzing Benchmark** — Fuzzing evaluation methodology
13. **2023 - FuzzGPT: Testing DL Libraries via LLMs** — LLM-guided fuzzing (edge case generation)
14. **2018 - PhASAR: Inter-procedural Static Analysis Framework** — C/C++ static taint tracking
15. **2017 - kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels** — Intel PT-based kernel fuzzing
16. **2022 - Sydr-Fuzz: Continuous Hybrid Fuzzing** — Concolic execution + grey-box integration
17. **2019 - PeriScope: Hardware-OS Boundary Fuzzing** — Firmware + CPU interaction testing
18. **2020 - P2IM: Automatic Peripheral Interface Modeling** — Firmware emulation without reversing
19. **2022 - POLYFUZZ: Holistic Greybox Fuzzing of Multi-Language Systems** — Language-agnostic fuzzing
20. **2023 - Beyond the Coverage Plateau: A Comprehensive Study of Fuzz Blockers** — Why fuzzing stalls (structural obstacles)

---

## Categories (Organized by Domain)

### Fuzzing Fundamentals & Mutation
- Corpus distillation, seed minimization, mutation scheduling, coverage guidance
- **Key**: DARWIN, MOpt, Alphuzz, BEACON, SelectFuzz, Graphuzz, LinFuzz

### Hybrid Fuzzing (Symbolic + Fuzzing)
- Concolic execution, taint inference, constraint solving
- **Key**: Driller, SymCC, SYMSAN, Ferry, CherryPicker, Sydr-Fuzz

### Directed Fuzzing & Vulnerability Hunting
- Reaching specific targets, constraint focusing, vulnerability-oriented directed fuzzing
- **Key**: TOFU, DDGF, DeepGo, Titan, Beacon, SelectFuzz, WindRanger

### Binary Analysis & Static Analysis
- Reverse engineering, type inference, graph analysis
- **Key**: PhASAR, What Exactly Determines Type, Nimbus, DAISY, GraphFuzz

### Firmware & IoT Security
- Emulation, peripheral modeling, firmware diffing, Bluetooth
- **Key**: P2IM, FirmXRay, Firm-AFL, FirmFuzz, PeriScope, QNAP/firmware tools

### Kernel & System-Level Fuzzing
- kAFL, system calls, device drivers, QEMU
- **Key**: kAFL, PeriScope, Drifuzz, MORPHUZZ, FASSFuzzer

### Memory Safety & Sanitizers
- ASAN, Valgrind, memory error detection, crash analysis
- **Key**: ParmeSan, FuZZan, QMSan, Casr-Cluster, AURORA

### Format-Specific & Structured Input
- File systems, protocols, grammars, binary formats
- **Key**: WEIZZ, Janus, CarpetFuzz, Logos, SpecFuzzer, NestFuzz

### Input Processing & Semantics
- Grammar inference, input specifications, magic bytes
- **Key**: REDQUEEN, Hopper, Look Ma No Input, NestFuzz, CarpetFuzz

### AI/LLM Integration
- LLM-guided fuzzing, ML-based scheduling, neural networks
- **Key**: FuzzGPT, SymRustC (Rust), autofz, CAMFuzz, reinforcement learning fuzzers

### Network & Protocol Fuzzing
- Stateful protocols, message sequences, network stacks
- **Key**: Logos, PeriScope, Triereme, Program Environment Fuzzing

### Root Cause Analysis
- Crash clustering, causal testing, bug classification, automated analysis
- **Key**: AURORA, RCABench, Casr-Cluster, ACRCA (automated recovery), BugDiversity

### Exploitation & Vulnerability Detection
- ROP chain generation, vulnerability primitives, exploit chains
- **Key**: A Review of Memory Errors (x86-64), AntiFuzz (fuzzing resistance)

### Compiler & Language-Specific Fuzzing
- C++, Rust, language-native fuzzers, type safety
- **Key**: SymRustC, CrabSandwich, DocTer, AutoGenD, PoliFuzz

### Testing & Verification Methodology
- Metamorphic testing, mutation analysis, coverage effectiveness
- **Key**: Mutation Analysis (Ansering Fuzzing Challenge), Evaluating Fuzz Testing, FuzzBench

### Performance & Optimization
- Fuzzer efficiency, resource management, scheduling algorithms
- **Key**: Boosting Fuzzer Efficiency (Information Theory), MemLock, UltraFuzz, Fuzzing at Scale

---

## By Application: CTF vs Bug Bounty vs Research

### Best for CTF (Reverse + Exploit)
1. **Symbolic Execution Papers**: SymCC, SYMSAN, Driller — for reversing math/crypto
2. **Binary Analysis**: PhASAR, type inference — for understanding binaries
3. **Crash Analysis**: AURORA, Casr-Cluster — for root cause extraction
4. **Memory Errors**: A Review of x86-64, ParmeSan — for buffer overflow patterns
5. **Constraint Solving**: Driller, Ferry — for multi-stage exploitation

**Why**: CTF targets are bounded, offline, and deterministic. Symbolic execution excels here.

### Best for Bug Bounty (Web + Smart Contracts)
1. **Web/Network Fuzzing**: Logos, Program Environment Fuzzing, POLYFUZZ
2. **Directed Fuzzing**: DeepGo, SelectFuzz, Titan — reach vulnerable code paths
3. **Input Processing**: WEIZZ, Hopper, NestFuzz — understand API validation
4. **Hybrid Fuzzing**: Sydr-Fuzz, CherryPicker — maximize test coverage
5. **Static Analysis**: PhASAR, CodeQL patterns — variant analysis

**Why**: Real targets have sprawling APIs, network dependencies, and complex validation. Directed + hybrid excels.

### Best for Security Research
1. **Surveys & SoKs**: Directed Greybox Fuzzing (SoK), Fuzz Blockers (NDSS 2024)
2. **Methodological**: FuzzBench, Magma, FixReverter — evaluation frameworks
3. **Novel Techniques**: REDQUEEN, MOpt, DARWIN — novel mutation/scheduling ideas
4. **Empirical Studies**: OSS-Fuzz Bugs, What Happens When We Fuzz
5. **Hardware**: kAFL, PeriScope — novel coverage mechanisms

**Why**: Research papers focus on generalizability, benchmarking, and novel insights.

---

## Tool-to-Paper Mapping (What Papers Led to What Tools)

| Tool | Key Papers | Impact |
|------|-----------|--------|
| **AFL** | Dissecting AFL, AFL++ | Coverage-guided fuzzing baseline |
| **libFuzzer** | Boosting Fuzzer Efficiency, MemLock | Continuous fuzzing harnesses |
| **QEMU+Fuzzing** | LibAFL QEMU, PeriScope | Firmware + system fuzzing |
| **angr** | Driller, SymCC | Symbolic execution engine |
| **libAFL** | LibAFL paper (2022) | Modular fuzzer composition |
| **Slither** (implied) | Static analysis SoK | Smart contract analysis |
| **Magma** | Magma paper (2020) | Fuzzing benchmark suite |
| **P2IM** | P2IM paper | Firmware emulation without reversing |
| **Driller** | Driller paper (2016) | Hybrid fuzzing (AFL + symbolic) |
| **QEMU-based fuzzers** | PeriScope, LibAFL QEMU | Hardware-boundary testing |
| **Casr** | Casr-Cluster (2021) | Crash deduplication |

---

## Recent Trends (2024-2025)

- **Predictive fuzzing**: DeepGo (2024) — neural networks predict promising targets
- **Grammar learning**: Grammar inference without specs (WASP 2024)
- **State-aware fuzzing**: DSFuzz (2023), Stateful fuzzing (2022)
- **Prompt engineering**: FuzzGPT (2023), AutoFuzz (2025) — LLM scheduling
- **Multi-target directed**: Titan (2023), multiple target optimization
- **Hardware acceleration**: Tango (2024) extracts higher-order feedback via CPU events
- **IoT/Firmware dominance**: 10+ new firmware fuzzing papers yearly (P2IM variants, emulation)

---

## Navigation by Paper Format

**Type**: Survey/SoK (systematic review)
- Directed Greybox Fuzzing (2020)
- Coverage Saturation (2023)
- Fuzz Blockers (2023)

**Type**: Framework/Tool
- LibAFL, AFL++, QEMU+Fuzzer, P2IM, Sydr-Fuzz

**Type**: Empirical Study
- OSS-Fuzz Bugs (2021), What Happens When We Fuzz (2023)

**Type**: Novel Technique
- REDQUEEN, DARWIN, SYMSAN, DeepGo

---

## Quick Start by Goal

- **"I want to build a fuzzer"** → LibAFL (2022), AFL++ (2020)
- **"I want to fuzz firmware"** → P2IM (2020), PeriScope (2019), LibAFL QEMU (2024)
- **"I want to reach specific code"** → SelectFuzz (2023), DeepGo (2024), Beacon (2022)
- **"I want symbolic execution"** → SymCC (2020), SYMSAN (2022), Driller (2016)
- **"I want to evaluate my fuzzer"** → FuzzBench (2022), Magma (2020), FixReverter (2022)
- **"I want static taint analysis"** → PhASAR (2018), CodeQL (various)
- **"I want LLM-guided testing"** → FuzzGPT (2023), AutoFuzz (2025)

---

**Total Papers Indexed**: 814 (read/tagged: 50+, unread: 760+)
**Last Updated**: Feb 2026
**Maintained at**: `~/tools/paper_collection/README.md`
