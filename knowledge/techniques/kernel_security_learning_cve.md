# Linux Kernel CVE Reference (2023-2026)

> Kernel exploit 학습 및 kernelCTF 참조용. CVE ID/서브시스템/기간은 공식 NVD,
> kernel.org CVE announce, Google kernelCTF 공개 disclosure 기준. 제출 전 최신
> 상태 재확인 필수.

---

## 1. kernelCTF 최근 공개 (2024-2026)

Google kernelCTF는 submission 공개 후 30일 정책으로 PoC + writeup이 공개 저장소에 업로드됨. 2024-2025 공개분에서 주요 패턴:

### 1.1 io_uring 계열 (지속적 핵심 surface)
- `io_uring_poll` 관련 race (CVE-2024-0582 family 후속)
- `io_uring_cmd` 특수 path 관련 UAF
- Buffer select (`IORING_OP_PROVIDE_BUFFERS`) 상태 동기화 오류
- **탐지 팁**: `io_uring` opcode 중 file lifetime 관리하는 경로는 race-prone

### 1.2 netfilter / nf_tables
- `nft_set_rbtree`, `nft_set_pipapo` 관련 UAF (CVE-2024-1086 이후 계보)
- `nft_chain_flush` / GC race
- Rule commit 중 race → UAF → kernel ROP
- **탐지 팁**: `nft_*_destroy` 호출 경로에서 rcu_call 이후 동일 객체 재참조 가능 여부

### 1.3 vsock / sockets
- `vsock_stream_sendmsg` UAF 계열
- AF_PACKET fanout 관련 race (CVE-2023-42752 계보)

### 1.4 tc classifier / filter
- 네트워크 스케줄러의 `tc_filter_release`/`tc_del_tfilter` 경로
- Queue discipline 동기화 gap

### 1.5 eBPF
- Verifier bound tracking bypass
- Helper TOCTOU (특히 ringbuf, map ops)
- `bpf_prog_run` 호출 시점 task state mismatch

---

## 2. 2025년 주요 공개 CVE 테마

다음은 2024-2025 커뮤니티/공식 disclosure에서 반복 관찰된 주제. 실제 CVE ID는 수시로 변경되므로 아래 키워드로 NVD/MITRE 검색 권장:

| 서브시스템 | 검색 키워드 | 대표 primitive |
|------------|-------------|----------------|
| io_uring | `CVE-2024 io_uring`, `CVE-2025 io_uring` | UAF, double-free, race |
| netfilter | `CVE-2024 netfilter`, `nft_set` | UAF after GC |
| eBPF | `bpf verifier CVE-2024/2025` | OOB read, type confusion |
| af_packet | `af_packet fanout race` | OOB write via shared buf |
| kvm | `kvm_nested`, `vmx_handle` | info leak, guest→host |
| fuse | `fuse_dev_do_read` | UAF on abort |
| tty / n_tty | `n_tty` race | classic, less frequent |
| usb | `USB gadget` | driver specific UAF |
| drm | `amdgpu`, `drm_sched` | UAF in scheduler cleanup |

---

## 3. Exploit Primitive → Technique 매핑 (2024-2026 관찰)

### 3.1 UAF → Cross-cache
- SLUB merging 특성 이용
- Page-level cross-cache (DirtyCow 계보)
- `cross-cache` + `msg_msg` / `pg_vec` / `setxattr` ID confusion

### 3.2 OOB → ROP/JOP
- kCFI 도입 이후 단순 indirect call 제어 어려움
- mitigations 활성화 환경(`kernelCTF mitigation` 인스턴스)에서는 data-only attack 선호
- modprobe_path overwrite는 여전히 유용하지만 패치 지속

### 3.3 Dirty PageTable
- 2022년 bsauce의 pipe_buffer → PT 기법 계보
- 2025년에는 `file` struct의 `f_pipe` 경로 등 변형 기법

### 3.4 Type Confusion
- eBPF map type 불일치
- RBTREE/LIST 연산에서 서로 다른 struct 참조

---

## 4. 학습 리소스

### 4.1 공식/커뮤니티
- **kernelCTF** — https://google.github.io/security-research/kernelctf/rules.html (규칙, submission 목록)
- **Project Zero blog** — issue tracker에 상세 writeup
- **bsauce kernel-security-learning** — UAF/heap/BPF/race/Dirty PageTable 22문서
- **syzbot** — https://syzkaller.appspot.com/upstream (활성 bug 목록)

### 4.2 개인 연구자/블로그
- Will's Root, Andy Nguyen (theflow), h0mbre, phoenhex 계보
- Chompie1337 (Windows 중심이지만 기법 응용)
- bsauce (한/중 서적 시리즈, UAF 기법 집대성)

### 4.3 실습 환경 (kernelCTF 스타일)
- `knowledge/techniques/kernelctf_lpe_environment.md` — Terminator에서 제공하는 LPE lab 가이드
- `kernel-exploits.com` 아카이브 (고전 CVE 실습)

---

## 5. 탐색 워크플로

신규 CVE 분석 시:
1. `syzbot`에서 active bug 선정 (reproduction 있음 우선)
2. `git log --since=1.month --grep="<subsystem>"`로 패치 커밋 스캔
3. 커밋 diff에서 신규 race/lock 도입 여부 관찰
4. `syz-prog` 또는 기존 PoC fork → 로컬 재현
5. Primitive 식별 → 3.1-3.4 기법 매핑
6. mitigations 활성화 환경에서 chain 설계

---

## 6. 바운티 프로그램

| 프로그램 | 범위 | 금액 |
|----------|------|------|
| Google kernelCTF | 업스트림/stable/mitigation/COS | 최대 $133,337 (mitigation bypass) |
| ZDI | 드라이버 포함 다수 타겟 | 주제별 |
| 벤더 프로그램 | RedHat, SUSE, Canonical 직접 | 비공개 |
| HackerOne IBB | 서브시스템별 공용 | 심사 |

---

## 7. 파이프라인 연계

- **reverser** (CTF): kernelCTF 제출 대상 분석 시 본 문서를 primitive 매핑 참조
- **solver**: mitigation 활성 시 섹션 3.1-3.4 data-only 기법 우선
- `knowledge/techniques/kernel_security_learning_main.md` (46KB) — 더 상세한 기법 문서 참조
- `knowledge/techniques/kernel_exploit_multistage.md` — 다단계 체인 설계

마지막 업데이트: 2026-04-16
