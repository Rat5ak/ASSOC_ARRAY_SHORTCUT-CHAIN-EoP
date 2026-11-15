# assoc_array: A Shortcut Behind a Shortcut

Unprivileged local user to root on a hardened Linux 7.2-rc5 kernel.

One `add_key` puts a shortcut node directly behind another shortcut node in a
keyring's associative array, which the tree treats as impossible. It BUG()s
and kills the inserting thread, but a reader parked in `key_link` walks the
broken tree anyway and lands on an attacker-owned object it believes is a
`struct key`. The kernel's own key-quota accounting then writes through an
aliased pointer into `cred->cap_effective`.

**I did not find this bug.** There's a public patch for it,
[`48691075b0ad`](https://github.com/torvalds/linux/commit/48691075b0adc590a6831390723e3603dfca76fc),
authored by Linus Torvalds, crediting Nils Ollrogge as the reporter. It hasn't
landed in mainline though: `torvalds/linux` master still has
`excised_meta[1]` where the patch makes it `[2]`, checked 2026-11-15. The
exploit chain is the only part I wrote. It was already public before I could
use it, and I'd have gotten smoked in kernelCTF with it anyway.

|            |                                                               |
|------------|---------------------------------------------------------------|
| CVE        | none assigned                                                 |
| Root cause | `assoc_array_insert_into_terminal_node()` replaces a full node with a shortcut; if that node was already a shortcut's target, the new shortcut lands behind the old one |
| Component  | `lib/assoc_array.c`, reached through `security/keys/`         |
| Introduced | `3cb989501c26`, the original `assoc_array` implementation    |
| Patch      | `48691075b0ad` adds a second `excised_meta[]` slot. Public, not in mainline as of 2026-11-15 |
| Trigger    | Eighteen insertions and a deletion, then one more `add_key(2)` |
| Privileges | Local unprivileged user. No capabilities, no namespaces       |
| Target     | kernelCTF hardened 7.2-rc5, bzImage `f8aeaf6e…`               |

## The Bug

`lib/assoc_array.c` is the kernel's RCU-safe radix tree, used almost entirely
by the keyrings code. It has nodes (16-slot fan-out levels) and shortcuts,
which compress a single-occupant subtree into one hop and store the skipped
index bits inline. A shortcut's parent is always a node, never another
shortcut, because the first would have absorbed the second's bits.

Deletion can leave a plain node below a shortcut. Insertion can then replace
that node with a shortcut, when the node's leaves and the new key all agree on
its segment and there is nothing left to split on. If that node was already a
shortcut's target, the new shortcut is installed as the old one's next node.
The fix commit gives the recipe: *"sixteen keys that agree on bits 0-11, one
that leaves them at bit 8 and is deleted again, and one more that agrees with
the sixteen."*

Two things then go wrong, and the exploit needs both. `assoc_array_walk()`
indexes the second shortcut **as a node**, so a reader mis-parses the skipped
bits and follows a pointer from the wrong level of the tree. And
`assoc_array_apply_edit()` hits its `BUG_ON()` on that same insertion:

```text
kernel BUG at lib/assoc_array.c:1387!
assoc_array_apply_edit+0x221/0x230
 __key_link+0x51/0x80
 __key_instantiate_and_link+0xc0/0x140
 __key_create_or_update+0x51a/0x580
 key_create_or_update+0x14/0x30
 __se_sys_add_key+0x1d0/0x240
```

The oops takes down only the inserting thread. The chain arranges for a
reader to be parked in `key_link` at exactly that moment, and it survives.

## The Gadget

The reader treats an attacker-owned allocation as a `struct key`. The chain
places it so the fake key's `user` pointer sits eight bytes below a real
`struct cred`:

```text
CRED_CAPTURE_PASS   cred=0xfffffe968c0436c0
PREP_PRIMARY_RETURN user=0xfffffe968c0436b8 CapEff=00000000ffffffff
```

`0xfffffe968c0436c0 - 8 == 0xfffffe968c0436b8`. `struct key_user` holds the
per-UID quota counters, and every key instantiation adjusts them through
`key->user`. Aliased into a credential, those adjustments land in the
capability words instead. That is the whole write primitive: the kernel's own
bookkeeping, at an eight-byte offset.

It is a capability escalation, not a uid one. `uid` stays 1000 and `CapEff`
goes from `0000000000000000` to `00000000ffffffff`: the low 32 bits, the
width of the aliased counter. `CAP_DAC_OVERRIDE` is in there, so a root-only
file becomes readable.

Getting a shell is a second step: holding `CAP_SETUID`, call
`setresuid(0,0,0)` and `execve`. The kernel sees an `execve` by euid 0 and
grants the full set legitimately, which is why the recording shows
`00000000ffffffff` from the gadget and then `000001ffffffffff` in the shell.
The first one is the bug. The second is just what the kernel hands any euid 0
process on execve.

## Demo

[![assoc_array shortcut-chain user-to-root](https://img.youtube.com/vi/RZuY0T6G_zE/maxresdefault.jpg)](https://youtu.be/RZuY0T6G_zE)

1:47. Also in [`demo/`](demo/root_shell_demo.mp4).

| | before | after |
|---|---|---|
| `id` | `uid=1000(user) gid=1000` | `uid=0(root) gid=0(root)` |
| `cat /flag` | `Permission denied` | `K2_DEV_FLAG_PREPARSE_CHAIN` |
| `CapEff` | `0000000000000000` | `000001ffffffffff` |

Root shell at 84 s on that take. Screen recording competes for the VM's two
vCPUs, so it is slower than the times below.

## Reliability

| build | boots | success |
|---|---|---|
| flag read + panic | 20 | **14** (70%) |
| root shell | 8 | **7** (88%) |

Both on the same hardened image, 2 vCPU. The root-shell build needs
`K2_AFALG_TIMEOUT_USEC=2000000`; at the compiled-in 500 ms it manages 2/8,
because the cred-capture stage does 1800 `open`/`close` and a 20 ms sleep
inside a per-sample budget sized for a stage that does 448 `keyctl` updates
and sleeps 1 ms.

The remaining failures are the race itself. The target key's allocation rank
has to land above 352 of 640 prepared workers, and a rank below that is
terminal for the run.

## Building

```bash
cd exploit
make
./exploit --selftest
```

The prebuilt binary is the tested one. Running the full chain needs the
matching hardened image and a kernelCTF-style initramfs, neither of which is
here.

```bash
/exploit                              # capability write, flag read
/exploit --vuln-trigger lts-6.12.114  # deterministic crash, LTS
```

## Credit

- Bug reported by **Nils Ollrogge**, fixed by **Linus Torvalds**, reviewed by
  **David Howells**
- `assoc_array_insert_into_terminal_node()` has been here twice before:
  [CVE-2016-7914](https://nvd.nist.gov/vuln/detail/CVE-2016-7914) and
  [CVE-2017-12193](https://nvd.nist.gov/vuln/detail/CVE-2017-12193). This is
  the third bug in that function.

## Don't be stupid

Lab artifact, built against one pinned kernel image in a VM. Run it on
systems you own. If you defend Linux boxes: patch past `48691075b0ad`, and
restricting unprivileged `AF_ALG` removes the heap oracle this chain needs.

---

> **Disclaimer:** This exploit code is provided for security research and
> educational purposes. Do not use it against systems you do not own or have
> explicit authorization to test. The author is not responsible for misuse.

*Daniel Wade - [GitHub](https://github.com/Rat5ak) · [Twitter/X](https://x.com/Nadsec11) · [Bluesky](https://bsky.app/profile/nadsec.online) · [Mastodon](https://cyberplace.social/@Nadsec) · [Medium](https://medium.com/@Nadsec) · [nadsec.online](https://nadsec.online)*
