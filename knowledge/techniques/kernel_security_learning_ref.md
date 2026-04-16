# Kernel Security Learning — Reference Index

Source: https://github.com/bsauce/kernel-security-learning (cloned 2026-03-24)
Author: bsauce

## Summary

Comprehensive kernel security resource covering CTF kernel pwn, real-world CVE exploits, kernel fuzzing, kernel defense research, and kernel debugging techniques. Chinese-language writeups with code and exploit samples.

## Indexed Files (in knowledge/techniques/)

| File | Content |
|------|---------|
| `kernel_security_learning_main.md` | Main README — full CTF/exploit/fuzz/defense/debug link collection |
| `kernel_security_learning_cve.md` | CVE exploit debug records (BPF overflow, CVE-2017-16995, CVE-2017-7184) |
| `kernel_security_learning_debug_SystemTap使用技巧.md` | SystemTap usage guide |
| `kernel_security_learning_debug_内核调试方法对比.md` | Kernel debugging method comparison |
| `kernel_security_learning_debug_使用Ftrace来Hook linux内核函数.md` | Ftrace kernel function hooking |

## Key Technique Categories

### CTF Kernel Pwn
- UAF (Use-After-Free): CISCN2017-babydriver, WCTF2018-klist, race UAF patterns
- Heap spray: sendmsg/msgsend, pipe heap spray, seq_operations spray
- Double-fetch / TOCTOU: 0CTF2018, TokyoWesterns2019
- Stack overflow: 2018强网杯-core, custom kernel modules
- Arbitrary R/W to LPE: 4 methods (modprobe_path, cred overwrite, etc.)
- msg_msg structure abuse for arbitrary addr R/W
- userfaultfd exploitation
- ret2dir technique
- Bypassing SLAB_FREELIST_HARDENED
- call_usermodehelper privilege escalation paths
- Cross-cache attacks, dirty pagetable, elastic objects

### Real CVEs Analyzed
- BPF integer overflow (kernel 4.20) — LPE
- CVE-2017-16995 — eBPF integer extension OOB
- CVE-2017-7184 — xfrm overflow

### Kernel Fuzzing
- Syzkaller setup and usage
- Kernel fuzzing papers and methodologies

### Kernel Defense / Mitigations
- KASLR, SMEP, SMAP, KPTI bypass techniques
- CONFIG_SLAB_FREELIST_HARDENED bypass
- Kernel CFI / KCFI research
- Exploitation mitigations timeline

### Debugging Techniques
- SystemTap: cross-compile, instrumentation, scripts
- Ftrace: kernel function hooking
- kprobe: dynamic tracing
- Kernel debug method comparison (GDB, KGDB, ftrace, SystemTap, perf)

## How to Search

Via knowledge-fts MCP (preferred):
```
smart_search("kernel UAF heap spray")
smart_search("eBPF exploit LPE")
smart_search("kernel TOCTOU double fetch")
technique_search("UAF")
technique_search("heap spray")
```

Via CLI:
```bash
python3 tools/knowledge_indexer.py search "kernel UAF" --table techniques
python3 tools/knowledge_indexer.py search "BPF overflow" --table techniques
```

## Tags
kernel, exploit, cve, ctf, pwn, UAF, heap-spray, BPF, race-condition, TOCTOU, dirty-pagetable, LPE, privilege-escalation, fuzzing, syzkaller, kaslr-bypass, smep-bypass
