# The profile template

A dev.site profile is one fixed piece of semantic HTML styled by [Pico CSS] and
nothing else. Personalisation happens through validated declarations, not rules:
Pico variables control appearance, while three dev.site variables control the
initial folder layout. That makes "is this profile declaration valid?" a question
the server can answer mechanically in `crates/devsite-server/src/theme.rs`.

[Pico CSS]: https://picocss.com

## What the page is made of

| Layer | File | Role |
| --- | --- | --- |
| Framework | `web/vendor/pico.min.css` | Pico 2.1.1, vendored. Styles semantic elements directly. |
| Site | `web/site.css` | The typeface, and the few layout rules Pico has no opinion about. No colours. |
| Theme | `<style id="profile-theme">` | One rule, written at render time, holding only `--pico-*` assignments. `--devsite-*` layout values never enter it. |

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

Rendered by `web/app.js`. Profile declarations are only meaningful against this
structure, so changes here and changes to the whitelist belong in the same commit.

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
        <!-- reached through its owner's daemon, so it is a button that opens
             the browser's ticket-minting prompt here. -->
        <li class="entry" data-kind="service" data-visibility="private">
          <button class="outline">Hermes</button>
          <small class="state">private</small>
        </li>
      </ul>

      <!-- then a fold per folder, in the owner's declared order followed by
           unlisted folders in the order they first appear -->
      <details class="folder" open>
        <summary>Games <small>3</small></summary>
        <ul class="entries">…</ul>
      </details>

      <!-- accepted shares use the same rows and folds, with "from @owner" in the name -->
    </article>
  </main>

  <dialog id="service-ticket-dialog">…Get ticket, then devsite connect…</dialog>
</body>
```

Everything on a profile is a site. `data-kind` says how you get to one — `link`
is reached at its own address, while `service` is a TCP byte stream reached with
`devsite connect`. The page does not sort itself into kinds, because which of the
two a thing is says nothing about what it is for.

`data-visibility` is on the row: `public`, `private` or `shared`. It is written
out in `.state` only where it is not `public`. For a link, visibility controls
who can discover the URL on dev.site; it cannot stop someone who already knows
the destination from opening or forwarding it. Shared links require recipient
approval, and changing their destination requires fresh approval.

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

A folder is a name on a site, not a thing of its own — `devsite link set --folder
Games` files one, and leaving `--folder` off takes it out again. There is nothing
to create and nothing to delete, so a profile can never be left holding an empty
one, and renaming a folder is retagging what is in it.

That falls out of the rendering too. The set of folders is derived from the
entries the visitor is allowed to see, so a folder holding only private sites does
not appear to a stranger as an empty fold — it is never built at all.

Folds are semantic `<details>` elements. They are open by default for profiles
without layout declarations. `--devsite-folders` changes that initial default,
and `--devsite-open-folders` names exceptions that start open. Once rendered,
the reader controls the ordinary open state. Pico draws the marker and handles
the interaction; `.folder > summary` is the label.

`--devsite-folder-order` names folders that should appear first. A name not
visible to the current visitor is ignored; visible folders omitted from the list
retain their first-appearance order. Folder names use JSON-style quoted strings,
the same non-control Unicode accepted by resource folders, with the same
40-scalar limit. Quotes and backslashes use JSON escapes.

`--pico-ins-color` and `--pico-del-color` are still in the whitelist, and are
what the page's success and failure messages are drawn with.

## What profile presentation may set

The list lives in `PROPERTIES` in `theme.rs` and is served at
`GET /api/theme/properties`, which is also what `devsite theme properties`
prints. Every `--pico-*` name in it is a variable the vendored Pico actually
defines. The three folder-layout names are consumed explicitly by `app.js` and
never emitted as CSS. An unrecognized name is rejected rather than accepted,
stored, and left to do nothing.

| Group | Properties | Value |
| --- | --- | --- |
| Scheme | `--devsite-scheme` | `light`, `dark` or `auto` |
| Layout | `--devsite-folders` | `open` or `closed` |
| | `--devsite-open-folders`, `--devsite-folder-order` | one or more quoted folder names |
| Surfaces | `--pico-background-color`, `--pico-color`, `--pico-muted-color`, `--pico-muted-border-color`, `--pico-border-color`, `--pico-text-selection-color` | colour |
| Accents | `--pico-primary` and its `-background`, `-hover`, `-hover-background`, `-inverse`, `-underline`, `-focus`; `--pico-secondary` and its `-background`, `-hover`, `-inverse`; `--pico-contrast` and its `-background`, `-inverse` | colour |
| Headings | `--pico-h1-color` … `--pico-h6-color` | colour |
| Blocks | `--pico-card-background-color`, `--pico-card-border-color`, `--pico-card-sectioning-background-color`, `--pico-code-background-color`, `--pico-code-color`, `--pico-mark-background-color`, `--pico-mark-color`, `--pico-blockquote-border-color`, `--pico-accordion-active-summary-color`, `--pico-accordion-close-summary-color`, `--pico-accordion-open-summary-color`, `--pico-ins-color`, `--pico-del-color` | colour |
| Form elements | `--pico-form-element-background-color`, `--pico-form-element-border-color`, `--pico-form-element-color` | colour |
| Effects | `--pico-box-shadow` | `unset` |
| Metrics | `--pico-border-radius`, `--pico-border-width`, `--pico-outline-width`, `--pico-spacing`, `--pico-block-spacing-vertical`, `--pico-block-spacing-horizontal`, `--pico-typography-spacing-vertical`, `--pico-form-element-spacing-vertical`, `--pico-form-element-spacing-horizontal`, `--pico-nav-element-spacing-vertical`, `--pico-nav-element-spacing-horizontal`, `--pico-text-underline-offset`, `--pico-font-size` | length |
| Type | `--pico-line-height` | number |
| | `--pico-font-weight` | `400` or `700` |
| | `--pico-text-decoration` | `none` or `underline` |

The `--devsite-*` keys are not Pico variables. `--devsite-scheme` sets
`data-theme` on the page, which is how Pico chooses between its own light and
dark palettes; the folder-layout keys are consumed as data while rendering the
semantic folds. `auto` leaves `data-theme` unset and follows the visitor's system
preference. Explicit `light` or `dark` forces that scheme.

### Value grammars

| Kind | Accepts |
| --- | --- |
| colour | `#rgb`, `#rgba`, `#rrggbb`, `#rrggbbaa`; `rgb()`, `rgba()`, `hsl()`, `hsla()`, `oklch()` over plain numbers; a CSS colour name; `transparent`; `currentcolor`; or `light-dark(<light-color>, <dark-color>)` containing exactly two of these colours |
| folder list | one or more comma-separated JSON-style strings containing non-empty, trimmed, non-control folder names of at most 40 Unicode scalar values |
| length | a non-negative number with `px`, `rem`, `em`, `ch`, `ex`, `vw`, `vh`, `vmin`, `vmax` or `%`, or bare `0` |
| number | a non-negative unitless number |

`var()`, `calc()` and `url()` are refused from CSS values. Every accepted Pico
value is drawn from the alphabet `[0-9a-z#%.,/()+- ]`, so it cannot carry `<`,
`"` or `}`. Folder names instead use the bounded JSON-string grammar and never
enter the generated `<style>` rule.

`light-dark()` uses its first colour in light mode and its second in dark mode.
Either side may use any supported colour form, including a functional colour:

```css
--devsite-scheme: auto;
--pico-primary: light-dark(#7b3fe4, #a982ff);
--pico-background-color: light-dark(rgb(250 248 255), rgb(24 18 32));
```

With `auto`, the pair follows the visitor's system preference. Setting
`--devsite-scheme: light` always selects the first colour; setting it to `dark`
always selects the second. The parser understands only this one level of
nesting: another `light-dark()`, `var()`, `calc()`, `url()`, or any other
function inside the pair is refused.

## What profile presentation cannot do

Refused outright, with a message naming the reason:

- selectors, braces, at-rules, and `!important`
- ordinary CSS properties — `position`, `display`, `content` and the rest
- Pico variables outside the list, including `--pico-font-family` and the
  `--pico-icon-*` data URIs

Pico declarations can recolour and re-space the template, and that is all.
Layout declarations may choose the initial open state and order of folders, but
they cannot remove a visible entry or prevent a reader from opening a fold.
Nothing can position, overlay, or load anything, so a profile you visit cannot
use its presentation to disguise itself as another part of the site.

## Setting one

From the CLI, and only from the CLI. The website reads profiles, manages account
controls, approves shares, and mints service tickets; links, hosted services,
sharing targets, themes, and folder layout are set with `devsite`. Claiming a
handle remains in the browser because that is where signing in finishes.

```bash
devsite theme properties          # what you may set
devsite theme show
devsite theme set my-theme.css    # or `-` for stdin
devsite theme clear
```

```css
/* my-theme.css */
--devsite-scheme: auto;
--devsite-folders: closed;
--devsite-open-folders: "Profiles";
--devsite-folder-order: "Profiles", "Services", "Games";
--pico-background-color: light-dark(#fefae0, #283618);
--pico-color: light-dark(#283618, #fefae0);
--pico-primary: light-dark(#bc6c25, #dda15e);
--pico-primary-hover: light-dark(#606c38, #fefae0);
--pico-accordion-active-summary-color: light-dark(#606c38, #dda15e);
--pico-accordion-close-summary-color: light-dark(#606c38, #dda15e);
--pico-accordion-open-summary-color: light-dark(#606c38, #dda15e);
--pico-box-shadow: unset;
--pico-border-radius: 0.5rem;
```

Rejections are specific and name the offending declaration:

```
--pico-primary: wine;   →  `--pico-primary: wine` — expected a colour, e.g. `#7b3fe4`, …
--pico-primary-color:   →  `--pico-primary-color` is not a profile property — did you mean `--pico-primary`?
body { color: red }     →  `{` is not allowed: a profile is a list of validated declarations
```

## Storage

Validated once, on write, by `PUT /api/theme`, and stored in
`profiles.custom_css` as canonical text — one `property: value;` per line. Every
later read treats the column as already-checked rather than re-deciding what is
safe. It is re-parsed on render anyway, so that a property retired from the
whitelist degrades a profile to the defaults instead of serving a rule the
current build no longer stands behind.
