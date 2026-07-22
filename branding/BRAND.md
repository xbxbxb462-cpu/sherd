# sherd brand guidelines

sherd is named after a *potsherd* — a broken fragment of pottery.
The name reflects what the tool does: it fragments secrets (Shamir
shares, chunked ciphertext) so that no single piece reveals anything.
Always write the name lowercase: **sherd**, never "Sherd" or "SHERD".

## Logo

| Asset | Use |
|---|---|
| `logo.png` | Light backgrounds (README on light mode, docs, print) |
| `logo-dark.png` | Dark backgrounds (README on dark mode, terminals, slides) |
| `social-preview.png` | GitHub social preview (Settings → Social preview, 1280x640) |

The mark is a hexagon fractured into shard fragments. Do not rotate,
recolor, outline, add effects, or place it on busy backgrounds.
Minimum clear space around the mark: half the mark's width.

## Color palette

| Token | Hex | Role |
|---|---|---|
| Shard Gold | `#D4A24E` | Primary accent — the brand color |
| Ink | `#171B26` | Primary dark — logo fragments, dark surfaces |
| Night | `#0C0F16` | Dark-mode background |
| Bone | `#E8E6E0` | Light text on dark surfaces |
| Slate | `#6B7280` | Secondary/muted text |

Never introduce additional accent colors. Gold is used sparingly —
it marks the "real" fragment, everything else stays dark and quiet.

## Typography

- Wordmark and code: a monospace face (JetBrains Mono, Geist Mono,
  or system monospace).
- Prose: the platform default sans-serif. sherd's brand voice lives
  in the terminal; the type should feel like a terminal.

## Voice

- Precise, technical, unhurried. State facts; never hype.
- Security claims are always falsifiable: name the primitive, the
  RFC, and the test that verifies it.
- Never promise "unbreakable" or "military-grade". The brand promise
  is *honest engineering under an adversarial threat model*.

## Tagline

> Offline encryption for adversarial conditions.

Acceptable short forms: "encryption that assumes the adversary is
competent."
