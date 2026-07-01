# Zal — LLM Reference Doc

**Purpose of this file.** Zal is a small language, created for Zat4, that no
language model has seen in training. This document is written to be **pasted into
an AI assistant as context** so it can write correct Zal for you. It states exactly
what the language can and cannot do, lists every input and function available, and
ends with complete, verified example programs. If you are an AI reading this:
**generate only what this document describes — do not assume any feature from C,
JavaScript, Python, or another language is present unless it is listed here.**

---

## 1. What Zal is, in one paragraph

Zal is a tiny, C-like language for writing **feed-ranking algorithms** on Zat4.
A Zal program is compiled to bytecode and run in a **sandbox on the reader's own
device**. It can compute anything mathematically, but it can reach **nothing**
outside a small, fixed set of inputs and functions — no network, no files, no
clock, no other users' data. That is not a rule it promises to follow; it is a
capability it does not have. Privacy is therefore structural: an algorithm that
does not call an attention function *cannot* read your attention data.

You write one function, `score()`, that is called **once per candidate post** and
returns a number. **Higher score = shown higher / more often.** That is the whole
job: given the facts about one post, return how good it is for this reader.

---

## 2. The one entry point

```
fn score() num {
    // ... compute using the facts + functions below ...
    return <a number>;
}
```

- The program **must** contain a function named exactly `score`.
- It takes **no parameters** — the current post's data arrives as the *facts* in
  §4, which you reference by name.
- It **returns a `num`** (see types below). Return a larger number for posts that
  should rank higher.
- You may write other `fn` declarations, but **only `score` is compiled, and it
  cannot call your other functions yet** — put all your logic inside `score`.

---

## 3. The type system (there is only one type)

- **`num`** — a single 64-bit floating-point number. That is the *only* type.
  There are no integers-vs-floats, no booleans, no strings, no arrays, no structs.
- **Booleans are numbers:** `true` is `1`, `false` is `0`. A comparison like
  `a > b` evaluates to `1` or `0`. In `if`/`while`, **any non-zero value is true**.
- Number literals are plain decimals: `1`, `42`, `3.14`, `0.5`, `100.0`.
  - **No exponent notation** (`1e5` is invalid — write `100000.0`).
  - **No hex, no underscores, no suffixes.**

---

## 4. The facts (the inputs to `score()`)

These are the public features of the current post. Reference them by name as if
they were variables. All are `num`.

| Fact | Meaning | Typical range |
|------|---------|---------------|
| `like_count` | number of likes | 0 … large |
| `repost_count` | number of reposts (amplification) | 0 … large |
| `reply_count` | number of replies (conversation) | 0 … large |
| `reply_chain` | times the author replied back into this thread (a strong positive) | 0 … |
| `quote_count` | number of quote-reposts (amplification with commentary) | 0 … large |
| `age_hrs` | hours since the post was created | 0 … large |
| `author_rep` | the author's public reputation prior | 0.0 … 1.0 |
| `in_network` | `1` if from an account you follow, else `0` | 0 or 1 |
| `viewer_engaged` | `1` if you already liked or reposted this post, else `0` | 0 or 1 |
| `tag_count` | how many topic tags (zones) this post carries | 0 … |
| `base_score` | the engine's own computed score for this post | any |

`base_score` lets you *refine* the engine's ranking; the other facts let you
compute a score *from scratch* (the flagship examples below do the latter, so the
whole mechanism is visible).

There are **no other facts.** There is no author identity, no post text, no
timestamp beyond `age_hrs`, no per-viewer identity — by design, so an algorithm
cannot target a specific account.

---

## 5. Functions you can call (capabilities)

These are the only callable functions. Each returns a `num`.

**Topic tags (public content).** Ask whether this post carries a named zone tag.
The tag is written as a quoted literal — a **text value is only ever a tag name**,
never used in arithmetic and never an author name. Reading tags is public and does
*not* make your algorithm "use behavioral data."

| Call | Returns |
|------|---------|
| `has_tag("zig")` | `1` if this post is in the `zig` zone, else `0` |

**On-device attention (adaptive personalization).** Reading either of these makes
your algorithm one that "uses behavioral data" — which is shown to the reader.
The data is read locally and can never leave the device.

| Call | Returns |
|------|---------|
| `attention_dwell()` | how long *this reader* lingered on this post, normalized `0.0 … 1.0` |
| `attention_clicked()` | `1` if this reader clicked into this post, else `0` |

**Persistent on-device memory (advanced — a learned model).** A small store that
survives across runs, indexed by a number. Also never leaves the device.

| Call | Returns |
|------|---------|
| `state_read(index)` | the stored value at `index` (0 if unset) |
| `state_write(index, value)` | writes `value` at `index`; returns 0 |

There are **no other functions.** No `print`, no `random`, no `now`, no `sqrt`,
no `exp`, no `pow`, no `log`, no math library. If you need a curve, build it from
`+ - * /` (see the recency idiom below).

> Retrieval functions (`follows`, `discovery`, `trending`) — which choose *which*
> posts enter the feed — exist but belong to a separate `retrieve()` entry point
> that is not yet available. **Do not call them from `score()`.**

---

## 6. Statements and control flow

```
var x = <expr>;          // declare a local variable (a num)
x = <expr>;              // assign to an already-declared variable
if (<expr>) { ... }                       // any non-zero condition is true
if (<expr>) { ... } else { ... }
if (<expr>) { ... } else if (<expr>) { ... } else { ... }
while (<expr>) { ... }   // loops while the condition is non-zero
return <expr>;           // return a value
<expr>;                  // an expression statement (e.g. state_write(0, x);)
```

- Variables must be **declared with `var` before use**. Assigning to an undeclared
  name is an error.
- **`while` is the only loop.** There is no `for`, no `break`, no `continue`.
  (The sandbox caps total steps, so an accidental infinite loop is stopped safely,
  but write terminating loops.)
- No `switch`, no `do/while`, no ternary `?:`, no `++`/`--`, no `+=`/`-=`.

---

## 7. Operators and precedence

From **lowest** to **highest** binding:

1. `||` (logical or)
2. `&&` (logical and)
3. `==`  `!=` (equality)
4. `<`  `>`  `<=`  `>=` (comparison)
5. `+`  `-` (add, subtract)
6. `*`  `/` (multiply, divide) — *division by zero yields 0, never an error*
7. unary `-` (negate), `!` (logical not)
8. `( )` grouping, function calls, literals, names

`!x` is `1` when `x` is `0`, else `0`. `&&`/`||` treat any non-zero value as true
and return `1`/`0`. Use parentheses when in doubt: `(a > b) && (c < d)`.

Comments are `//` to end of line only. **No `/* */` block comments.**

---

## 8. Idioms (how to do common things without a math library)

- **Rational recency decay** (there is no `exp`): a value that starts near 1 and
  fades as a post ages, with a "half-feel" of about `w` hours:
  ```
  var freshness = w / (age_hrs + w);   // e.g. 6.0 / (age_hrs + 6.0)
  ```
- **Velocity** (reward fast-accruing engagement):
  ```
  var velocity = 1.0 + (repost_count + reply_count) / (age_hrs + 2.0);
  ```
- **A cold-start floor** (so a brand-new post with 0 engagement still ranks above
  nothing): add a small constant to the engagement sum: `eng = eng + 1.0;`.
- **A conditional multiplier** (boost/dampen): use `if`:
  ```
  if (!in_network && eng > 150.0) { s = s * 1.4; }   // discovery boost
  if (age_hrs > 48.0) { s = s * 0.4; }               // stale dampener
  ```
- **Clamp-free min/max:** there is no `min`/`max` in the language surface; express
  choices with `if` instead.

---

## 9. Complete, verified programs

Every program below **compiles and runs** — copy them as starting points.

### Zat4 Discover (Twitter-Heavy-Ranker-flavoured, adaptive)

```
fn score() num {
  // Public engagement, weighted like Twitter's ranker (a reply >> a like).
  var eng = like_count + repost_count * 2.0 + reply_count * 27.0;
  // On-device attention (adaptive): your dwell + clicks, read locally.
  eng = eng + attention_dwell() * 20.0 + attention_clicked() * 24.0;
  // Cold-start floor: a brand-new post still gets a small chance.
  eng = eng + 1.0;
  // Freshness: a soft, deterministic ~6h decay (no exponential needed).
  var s = eng * (6.0 / (age_hrs + 6.0));
  // Velocity: reward fast-accruing amplification + conversation.
  s = s * (1.0 + (repost_count + reply_count) / (age_hrs + 2.0));
  // A mild public author-reputation prior.
  s = s * (1.0 + author_rep * 0.5);
  // Out-of-network discovery: lift strong posts from beyond your follows.
  if (!in_network && eng > 150.0) { s = s * 1.4; }
  // Stale guard: push day-old+ content down.
  if (age_hrs > 48.0) { s = s * 0.4; }
  return s;
}
```

### Zat4 Private Discover (zero behavioral data)

```
fn score() num {
  // Public engagement ONLY; replies weighted even harder (conversation-first).
  var eng = like_count + repost_count * 2.0 + reply_count * 40.0;
  eng = eng + 1.0;
  var s = eng * (4.0 / (age_hrs + 4.0));   // a fresher window than Discover
  s = s * (1.0 + (repost_count + reply_count) / (age_hrs + 2.0));
  s = s * (1.0 + author_rep * 0.5);
  if (!in_network && eng > 150.0) { s = s * 1.4; }
  if (age_hrs > 48.0) { s = s * 0.4; }
  return s;
}
```

### Simple starters

```
// Most Liked
fn score() num { return like_count; }

// Most Recent (newest first)
fn score() num { return 0.0 - age_hrs; }

// Calm — temper pile-ons: reward some conversation but divide by crowd size.
fn score() num {
  var eng = like_count + reply_count * 4.0;
  return eng / (1.0 + (repost_count + reply_count) / 20.0);
}
```

---

## 10. Checklist for generating valid Zal

Before returning Zal, verify:

- [ ] There is exactly one `fn score() num { ... }` and it ends by returning a `num`.
- [ ] Only the facts in §4 and the functions in §5 are used — nothing else.
- [ ] Only `num` values, plain decimal literals, and the operators in §7.
- [ ] Loops are `while` only; no `for`, `break`, `continue`, `switch`, ternary,
      `++`/`--`, or compound assignment.
- [ ] No `exp`/`pow`/`sqrt`/`log`/`random`/`min`/`max`/`print` — build curves from
      `+ - * /` (see §8).
- [ ] Every variable is `var`-declared before assignment.
- [ ] Comments are `//` only.
- [ ] `retrieve`/user-defined helper calls are **not** used inside `score()`.

If a request needs something Zal doesn't have, say so plainly rather than inventing
syntax — an algorithm that doesn't compile helps no one.
