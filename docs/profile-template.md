# The profile template

A dev.site profile is one fixed piece of semantic HTML styled by [Pico CSS] and
nothing else. Personalisation happens by assigning Pico's own variables, not by
writing rules — which is what makes "is this theme valid?" a question the server
can answer mechanically, in `crates/devsite-server/src/theme.rs`.

[Pico CSS]: https://picocss.com

## What the page is made of

| Layer | File | Role |
| --- | --- | --- |
| Framework | `web/vendor/pico.min.css` | Pico 2.1.1, vendored. Styles semantic elements directly. |
| Site | `web/site.css` | The typeface, and the few layout rules Pico has no opinion about. No colours. |
| Theme | `<style id="profile-theme">` | One rule, written at render time, holding only `--pico-*` assignments. |

They load in that order, and the theme is written as one rule:

```css
:root[data-profile="alice"] { --pico-primary: #bc6c25; … }
```

The `:root` is not decoration. Pico sets its palette on
`:root:not([data-theme=dark])`, which is specificity **(0,2,0)** — `:not()`
contributes the weight of its argument. A bare `[data-profile="alice"]` is
(0,1,0) and loses to that outright, however late it appears in the document.
Matching (0,2,0) and coming last is what makes a theme win.

This was wrong in the first implementation, and it failed silently: themes
validated, stored, served in the profile response, and applied to a page that
went on looking exactly the same. Nothing short of reading a computed style in a
real browser would have caught it, which is now how it is checked.

A theme still writes no selectors of its own — that one is supplied here, and the
user supplies only the declarations inside it.

**Type is fixed.** Open Sans, vendored at `web/vendor/fonts/`, at 400 and 700 and
no other weight. The file is a variable font, so it is declared twice at those two
weights rather than as a range: a request for 600 — which Pico makes in a couple
of places — resolves to 700 instead of rendering an in-between instance. There is
no `--pico-font-family` in the whitelist.

## The template

Rendered by `web/app.js`. A theme is only meaningful against this structure, so
changes here and changes to the whitelist belong in the same commit.

```html
<body>
  <header class="container">
    <nav>…wordmark…<ul id="session">…</ul></nav>
  </header>

  <main class="container" id="main">
    <article id="profile">
      <hgroup>
        <h1>@alice</h1>
        <p>3 sites</p>
      </hgroup>

      <!-- loose sites first, in the order they were published -->
      <ul class="entries">
        <!-- reached at its own address, so it is an anchor and takes you away.
             The host is always present and folded into the arrow; see below. -->
        <li class="entry" data-kind="link" data-visibility="public">
          <a href="https://klot.ski" target="_blank" rel="noopener noreferrer">klot.ski</a>
          <small class="state"><span class="host"><span>klot.ski&nbsp;</span></span>↗</small>
        </li>
        <!-- reached through its owner's daemon, so it is a button and opens
             here. No reachability state: nothing knows whether it is running
             until you ask it. -->
        <li class="entry" data-kind="service" data-visibility="private">
          <button class="outline">Hermes</button>
          <small class="state">private</small>
        </li>
      </ul>

      <!-- then a fold per folder, in the order those first appear -->
      <details class="folder" open>
        <summary>Games <small>3</small></summary>
        <ul class="entries">…</ul>
      </details>

      <!-- other people's sites, on your own profile only -->
      <section class="group" data-visibility="shared-with-me">
        <h2>Shared with me</h2>
        <ul class="entries">…</ul>
      </section>
    </article>
  </main>

  <dialog id="viewer">…the service, in a sandboxed iframe…</dialog>
</body>
```

Everything on a profile is a site. `data-kind` says how you get to one — `link`
is reached at its own address, `service` through its owner's daemon — and that is
the only difference there is. The page does not sort itself into kinds, because
which of the two a thing is says nothing about what it is for.

`data-visibility` is on the row: `public`, `private` or `shared`. It is written
out in `.state` only where it is not `public`, and a link is always `public` —
dev.site can hide a URL but cannot stop anyone holding it from opening it, so
concealment is the only thing "private" could mean there and the word is not
offered.

There is deliberately no reachability state to style: the page does not know
whether a daemon is running, and says so by saying nothing.

### The host

Every link carries its host, including the ones named after it. At rest you see
the arrow; pointing at a row expands the host leftward out of it, so two repos
can both say `github.com` without two rows saying it at once.

`.host` is an inline grid whose single column animates `0fr → 1fr`, which reaches
exactly the content's width — a `max-width` would need a guess, and a wrong guess
either clips a long host or spends the transition crossing empty space. The
trailing space sits inside the clipped inner span so it collapses with the text
rather than leaving a gap before the arrow. Where there is no hover to ask with,
`@media (hover: none)`, the host is simply always shown.

## Folders

A folder is a name on a site, not a thing of its own — `devsite link add --folder
Games` files one, and leaving `--folder` off takes it out again. There is nothing
to create and nothing to delete, so a profile can never be left holding an empty
one, and renaming a folder is retagging what is in it.

That falls out of the rendering too. The set of folders is derived from the
entries the viewer is allowed to see, so a folder holding only private sites does
not appear to a stranger as an empty fold — it is never built at all.

Folds are `<details open>`. A profile's job is to show what is on it, so a folder
groups without hiding, and collapsing is the reader's choice rather than the
owner's. Pico draws the marker and handles the open state; `.folder > summary`
is the label.

`--pico-ins-color` and `--pico-del-color` are still in the whitelist, and are
what the viewer's success and failure messages are drawn with.

## What a theme may set

The list lives in `PROPERTIES` in `theme.rs` and is served at
`GET /api/theme/properties`, which is also what `devsite theme properties`
prints. Every name in it is a variable the vendored Pico actually defines; a name
Pico does not define would be accepted, stored, and quietly do nothing, which is
the failure mode the list exists to prevent.

| Group | Properties | Value |
| --- | --- | --- |
| Scheme | `--devsite-scheme` | `light`, `dark` or `auto` |
| Surfaces | `--pico-background-color`, `--pico-color`, `--pico-muted-color`, `--pico-muted-border-color`, `--pico-border-color`, `--pico-text-selection-color` | colour |
| Accents | `--pico-primary` and its `-background`, `-hover`, `-hover-background`, `-inverse`, `-underline`, `-focus`; `--pico-secondary` and its `-background`, `-hover`, `-inverse`; `--pico-contrast` and its `-background`, `-inverse` | colour |
| Headings | `--pico-h1-color` … `--pico-h6-color` | colour |
| Blocks | `--pico-card-background-color`, `--pico-card-border-color`, `--pico-card-sectioning-background-color`, `--pico-code-background-color`, `--pico-code-color`, `--pico-mark-background-color`, `--pico-mark-color`, `--pico-blockquote-border-color`, `--pico-ins-color`, `--pico-del-color` | colour |
| Form elements | `--pico-form-element-background-color`, `--pico-form-element-border-color`, `--pico-form-element-color` | colour |
| Metrics | `--pico-border-radius`, `--pico-border-width`, `--pico-outline-width`, `--pico-spacing`, `--pico-block-spacing-vertical`, `--pico-block-spacing-horizontal`, `--pico-typography-spacing-vertical`, `--pico-form-element-spacing-vertical`, `--pico-form-element-spacing-horizontal`, `--pico-nav-element-spacing-vertical`, `--pico-nav-element-spacing-horizontal`, `--pico-text-underline-offset`, `--pico-font-size` | length |
| Type | `--pico-line-height` | number |
| | `--pico-font-weight` | `400` or `700` |
| | `--pico-text-decoration` | `none` or `underline` |

`--devsite-scheme` is the one key that is not a Pico variable. It sets
`data-theme` on the page, which is how Pico chooses between its own light and
dark palettes; the rest of the theme then adjusts that starting point.

### Value grammars

| Kind | Accepts |
| --- | --- |
| colour | `#rgb`, `#rgba`, `#rrggbb`, `#rrggbbaa`; `rgb()`, `rgba()`, `hsl()`, `hsla()`, `oklch()` over plain numbers; a CSS colour name; `transparent`; `currentcolor` |
| length | a non-negative number with `px`, `rem`, `em`, `ch`, `ex`, `vw`, `vh`, `vmin`, `vmax` or `%`, or bare `0` |
| number | a non-negative unitless number |

`var()`, `calc()` and `url()` are refused everywhere. Every accepted value is
drawn from the alphabet `[0-9a-z#%.,/()+- ]`, so it cannot carry `<`, `"` or `}`
— the rendered rule is safe to inline in a `<style>` element as a property of the
grammar, not of an escaping step someone has to remember.

## What a theme cannot do

Refused outright, with a message naming the reason:

- selectors, braces, at-rules, and `!important`
- ordinary CSS properties — `position`, `display`, `content` and the rest
- Pico variables outside the list, including `--pico-font-family` and the
  `--pico-icon-*` data URIs

So a theme can recolour and re-space the template, and that is all. It cannot
position anything, hide anything, overlay anything, or load anything. A profile
you visit cannot use its theme to disguise itself as another part of the site.

## Setting one

From the CLI, and only from the CLI. The website is where a profile is read, not
where it is written — links, exposures, sharing and themes are all set with
`devsite`, and a theme is no more a browser concern than an exposure is. The one
exception is claiming a handle, which has to happen in the browser because that
is where signing in finishes.

```bash
devsite theme properties          # what you may set
devsite theme show
devsite theme set my-theme.css    # or `-` for stdin
devsite theme clear
```

```css
/* my-theme.css */
--devsite-scheme: dark;
--pico-primary: #7b3fe4;
--pico-primary-hover: #8f5bea;
--pico-border-radius: 0.5rem;
--pico-font-weight: 400;
```

Rejections are specific and name the offending declaration:

```
--pico-primary: wine;   →  `--pico-primary: wine` — expected a colour, e.g. `#7b3fe4`, …
--pico-primary-color:   →  `--pico-primary-color` is not a theme property — did you mean `--pico-primary`?
body { color: red }     →  `{` is not allowed: a theme is a list of `--pico-…: value;` declarations
```

## Storage

Validated once, on write, by `PUT /api/theme`, and stored in
`profiles.custom_css` as canonical text — one `property: value;` per line. Every
later read treats the column as already-checked rather than re-deciding what is
safe. It is re-parsed on render anyway, so that a property retired from the
whitelist degrades a profile to the defaults instead of serving a rule the
current build no longer stands behind.
