//! User themes.
//!
//! A profile's look is not a stylesheet. It is a list of assignments to named
//! Pico variables, each with a declared value grammar — so "is this theme
//! valid?" is a question with a mechanical answer rather than a judgement call.
//!
//! Two things follow from that, and both are the point:
//!
//! - **It cannot break the page.** No selectors, no properties, no at-rules, no
//!   `!important`. A theme can only recolour and re-space what the profile
//!   template already lays out; it cannot position, hide, or overlay anything.
//! - **It cannot inject.** Every property name is one of the `&'static str`s in
//!   [`PROPERTIES`], and every value has passed a grammar whose alphabet is
//!   `[0-9a-z#%.,/()+- ]`. Neither can carry `<`, `"` or `}`, so the emitted
//!   rule is safe to inline in a `<style>` element without further escaping.
//!
//! The variables below all exist in the vendored Pico 2.1.1. A name that Pico
//! does not define would be accepted, stored, and do nothing — which is exactly
//! the silent failure this list is here to prevent.

use serde::Serialize;

/// Longest accepted source, before parsing. A theme is a few dozen short lines.
pub const MAX_INPUT: usize = 4096;
/// Longest accepted value. This leaves room for two functional colours inside
/// `light-dark()` without changing the overall [`MAX_INPUT`] bound.
pub const MAX_VALUE: usize = 128;

/// One validated assignment. `property` is borrowed from [`PROPERTIES`], so a
/// stored declaration cannot name anything outside the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Declaration {
    pub property: &'static str,
    pub value: String,
}

/// The grammar a property's value must satisfy.
enum Kind {
    /// Hex, `rgb()`/`rgba()`/`hsl()`/`hsla()`/`oklch()`, a CSS colour name,
    /// `transparent`, `currentcolor`, or exactly two of those in `light-dark()`.
    Color,
    /// A non-negative number with a unit, or bare `0`.
    Length,
    /// A non-negative unitless number.
    Number,
    /// One of a fixed set of words.
    Keyword(&'static [&'static str]),
}

/// The one key that is not a Pico variable: it chooses which of Pico's own
/// palettes the profile starts from, by setting `data-theme` on the page.
pub const SCHEME: &str = "--devsite-scheme";

/// Every property a theme may set, with the grammar of its value.
///
/// Ordered as it is documented: scheme, then colour, then metrics, then type.
const PROPERTIES: &[(&str, Kind)] = &[
    (SCHEME, Kind::Keyword(&["light", "dark", "auto"])),
    // -- surfaces and text ---------------------------------------------------
    ("--pico-background-color", Kind::Color),
    ("--pico-color", Kind::Color),
    ("--pico-muted-color", Kind::Color),
    ("--pico-muted-border-color", Kind::Color),
    ("--pico-border-color", Kind::Color),
    ("--pico-text-selection-color", Kind::Color),
    // -- accents -------------------------------------------------------------
    ("--pico-primary", Kind::Color),
    ("--pico-primary-background", Kind::Color),
    ("--pico-primary-hover", Kind::Color),
    ("--pico-primary-hover-background", Kind::Color),
    ("--pico-primary-inverse", Kind::Color),
    ("--pico-primary-underline", Kind::Color),
    ("--pico-primary-focus", Kind::Color),
    ("--pico-secondary", Kind::Color),
    ("--pico-secondary-background", Kind::Color),
    ("--pico-secondary-hover", Kind::Color),
    ("--pico-secondary-inverse", Kind::Color),
    ("--pico-contrast", Kind::Color),
    ("--pico-contrast-background", Kind::Color),
    ("--pico-contrast-inverse", Kind::Color),
    // -- headings ------------------------------------------------------------
    ("--pico-h1-color", Kind::Color),
    ("--pico-h2-color", Kind::Color),
    ("--pico-h3-color", Kind::Color),
    ("--pico-h4-color", Kind::Color),
    ("--pico-h5-color", Kind::Color),
    ("--pico-h6-color", Kind::Color),
    // -- blocks --------------------------------------------------------------
    ("--pico-card-background-color", Kind::Color),
    ("--pico-card-border-color", Kind::Color),
    ("--pico-card-sectioning-background-color", Kind::Color),
    ("--pico-code-background-color", Kind::Color),
    ("--pico-code-color", Kind::Color),
    ("--pico-mark-background-color", Kind::Color),
    ("--pico-mark-color", Kind::Color),
    ("--pico-blockquote-border-color", Kind::Color),
    ("--pico-accordion-active-summary-color", Kind::Color),
    ("--pico-accordion-close-summary-color", Kind::Color),
    ("--pico-accordion-open-summary-color", Kind::Color),
    // `ins` and `del` also colour the site's own confirmations and refusals.
    ("--pico-ins-color", Kind::Color),
    ("--pico-del-color", Kind::Color),
    // -- form elements -------------------------------------------------------
    ("--pico-form-element-background-color", Kind::Color),
    ("--pico-form-element-border-color", Kind::Color),
    ("--pico-form-element-color", Kind::Color),
    // -- effects -------------------------------------------------------------
    // A profile may remove Pico's global shadow, but may not supply arbitrary
    // shadow syntax that could visually escape the component it belongs to.
    ("--pico-box-shadow", Kind::Keyword(&["unset"])),
    // -- metrics -------------------------------------------------------------
    ("--pico-border-radius", Kind::Length),
    ("--pico-border-width", Kind::Length),
    ("--pico-outline-width", Kind::Length),
    ("--pico-spacing", Kind::Length),
    ("--pico-block-spacing-vertical", Kind::Length),
    ("--pico-block-spacing-horizontal", Kind::Length),
    ("--pico-typography-spacing-vertical", Kind::Length),
    ("--pico-form-element-spacing-vertical", Kind::Length),
    ("--pico-form-element-spacing-horizontal", Kind::Length),
    ("--pico-nav-element-spacing-vertical", Kind::Length),
    ("--pico-nav-element-spacing-horizontal", Kind::Length),
    ("--pico-text-underline-offset", Kind::Length),
    ("--pico-font-size", Kind::Length),
    ("--pico-line-height", Kind::Number),
    // The typeface is fixed: Open Sans, at one of its two weights. There is no
    // --pico-font-family here, and that is deliberate.
    ("--pico-font-weight", Kind::Keyword(&["400", "700"])),
    (
        "--pico-text-decoration",
        Kind::Keyword(&["none", "underline"]),
    ),
];

/// Read a theme, or say precisely what is wrong with it.
///
/// The error is written for the person who typed the CSS, because it is shown
/// to them verbatim by both the website and the CLI.
pub fn parse(input: &str) -> Result<Vec<Declaration>, String> {
    if input.len() > MAX_INPUT {
        return Err(format!("a theme may be at most {MAX_INPUT} characters"));
    }

    let source = strip_comments(input)?;
    let mut declarations: Vec<Declaration> = Vec::new();

    for chunk in source.split(';') {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        if let Some(bad) = chunk.chars().find(|c| "{}@<>\"'\\".contains(*c)) {
            return Err(format!(
                "`{bad}` is not allowed: a theme is a list of `--pico-…: value;` \
                 declarations, not a stylesheet"
            ));
        }
        if chunk.contains('!') {
            return Err(
                "`!important` is not allowed; a theme never has to out-rank anything".into(),
            );
        }

        let (name, value) = chunk
            .split_once(':')
            .ok_or_else(|| format!("`{chunk}` is missing a `:`"))?;
        let name = name.trim().to_ascii_lowercase();
        let value = normalize_whitespace(value);

        if value.is_empty() {
            return Err(format!("`{name}` has no value"));
        }
        if value.len() > MAX_VALUE {
            return Err(format!("the value of `{name}` is too long"));
        }

        let (property, kind) = PROPERTIES
            .iter()
            .find(|(known, _)| *known == name)
            .ok_or_else(|| unknown_property(&name))?;

        if !kind.accepts(&value) {
            return Err(format!("`{name}: {value}` — expected {}", kind.describe()));
        }

        // Last one wins, as it would in a real rule block, but the theme keeps
        // the order it was written in. Collapsing duplicates here is also what
        // bounds the result: a theme can never hold more declarations than
        // PROPERTIES has entries, however long its source is.
        match declarations.iter_mut().find(|d| d.property == *property) {
            Some(existing) => existing.value = value,
            None => declarations.push(Declaration { property, value }),
        }
    }

    Ok(declarations)
}

/// Render declarations back to the canonical text stored in the database.
pub fn to_css(declarations: &[Declaration]) -> String {
    declarations
        .iter()
        .map(|d| format!("{}: {};\n", d.property, d.value))
        .collect()
}

/// Every property a theme may set, for `devsite theme properties` and the docs.
pub fn properties() -> impl Iterator<Item = (&'static str, String)> {
    PROPERTIES
        .iter()
        .map(|(name, kind)| (*name, kind.describe()))
}

fn unknown_property(name: &str) -> String {
    // A near miss is nearly always a typo, or a real Pico variable that is not
    // offered here, so point at the most specific thing that is.
    let stem = name.trim_start_matches("--pico-").trim_start_matches("--");
    let closest = PROPERTIES
        .iter()
        .map(|(known, _)| *known)
        .filter(|known| {
            let known_stem = known.trim_start_matches("--pico-").trim_start_matches("--");
            stem.len() >= 4 && (stem.contains(known_stem) || known_stem.contains(stem))
        })
        .max_by_key(|known| known.len());

    match closest {
        Some(known) => format!("`{name}` is not a theme property — did you mean `{known}`?"),
        None => {
            format!("`{name}` is not a theme property; run `devsite theme properties` for the list")
        }
    }
}

impl Kind {
    fn accepts(&self, value: &str) -> bool {
        match self {
            Kind::Color => is_color(value),
            Kind::Length => is_length(value),
            Kind::Number => is_number(value),
            Kind::Keyword(allowed) => allowed.contains(&value.to_ascii_lowercase().as_str()),
        }
    }

    fn describe(&self) -> String {
        match self {
            Kind::Color => "a colour, e.g. `#7b3fe4`, `rgb(123 63 228)`, `rebeccapurple` or `light-dark(#7b3fe4, #a982ff)`".into(),
            Kind::Length => "a length, e.g. `0.5rem`, `12px` or `0`".into(),
            Kind::Number => "a number, e.g. `1.5`".into(),
            Kind::Keyword(allowed) => format!("one of {}", allowed.join(", ")),
        }
    }
}

// -- value grammars -----------------------------------------------------------

fn is_color(value: &str) -> bool {
    let value = value.to_ascii_lowercase();

    if let Some(args) = value
        .strip_prefix("light-dark(")
        .and_then(|rest| rest.strip_suffix(')'))
    {
        return split_color_pair(args)
            .is_some_and(|(light, dark)| is_flat_color(light) && is_flat_color(dark));
    }

    is_flat_color(&value)
}

/// Split the arguments of `light-dark()` at its one top-level comma.
///
/// Commas inside an existing functional colour belong to that colour. Tracking
/// their parentheses here permits `rgba(1, 2, 3, 0.5)` on either side while
/// still rejecting unbalanced input and any third top-level argument.
fn split_color_pair(args: &str) -> Option<(&str, &str)> {
    let mut depth = 0_u8;
    let mut separator = None;

    for (index, character) in args.char_indices() {
        match character {
            '(' => depth = depth.checked_add(1)?,
            ')' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 && separator.is_some() => return None,
            ',' if depth == 0 => separator = Some(index),
            _ => {}
        }
    }

    if depth != 0 {
        return None;
    }

    let separator = separator?;
    let light = args[..separator].trim();
    let dark = args[separator + 1..].trim();
    (!light.is_empty() && !dark.is_empty()).then_some((light, dark))
}

/// The original, deliberately flat colour grammar. Keeping it separate makes
/// `light-dark()` the only supported nesting layer: neither side can introduce
/// another `light-dark()`, `var()`, `calc()`, `url()`, or arbitrary function.
fn is_flat_color(value: &str) -> bool {
    if value == "transparent" || value == "currentcolor" {
        return true;
    }
    if let Some(hex) = value.strip_prefix('#') {
        return matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if let Some((function, rest)) = value.split_once('(') {
        let Some(args) = rest.strip_suffix(')') else {
            return false;
        };
        return matches!(function, "rgb" | "rgba" | "hsl" | "hsla" | "oklch")
            && !args.trim().is_empty()
            // No nested functions, no var(), no url(): a flat list of numbers.
            && args
                .bytes()
                .all(|b| b.is_ascii_digit() || b" .,%/+-".contains(&b))
            && args.split([',', ' ', '/']).filter(|a| !a.is_empty()).count() <= 4;
    }
    NAMED_COLORS.binary_search(&value).is_ok()
}

fn is_length(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    const UNITS: &[&str] = &[
        "px", "rem", "em", "ch", "ex", "vw", "vh", "vmin", "vmax", "%",
    ];
    UNITS.iter().any(|unit| {
        value
            .strip_suffix(unit)
            .is_some_and(|number| !number.is_empty() && is_number(number))
    })
}

/// Non-negative, and no exponents: `1e9rem` is a length, but not a useful one.
fn is_number(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && value.matches('.').count() <= 1
        && value != "."
        && value.len() <= 8
}

fn strip_comments(input: &str) -> Result<String, String> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find("*/").ok_or("a comment is not closed")?;
        // A comment separates tokens, so it cannot simply vanish.
        out.push(' ');
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The CSS named colours, sorted for `binary_search`.
const NAMED_COLORS: &[&str] = &[
    "aliceblue",
    "antiquewhite",
    "aqua",
    "aquamarine",
    "azure",
    "beige",
    "bisque",
    "black",
    "blanchedalmond",
    "blue",
    "blueviolet",
    "brown",
    "burlywood",
    "cadetblue",
    "chartreuse",
    "chocolate",
    "coral",
    "cornflowerblue",
    "cornsilk",
    "crimson",
    "cyan",
    "darkblue",
    "darkcyan",
    "darkgoldenrod",
    "darkgray",
    "darkgreen",
    "darkgrey",
    "darkkhaki",
    "darkmagenta",
    "darkolivegreen",
    "darkorange",
    "darkorchid",
    "darkred",
    "darksalmon",
    "darkseagreen",
    "darkslateblue",
    "darkslategray",
    "darkslategrey",
    "darkturquoise",
    "darkviolet",
    "deeppink",
    "deepskyblue",
    "dimgray",
    "dimgrey",
    "dodgerblue",
    "firebrick",
    "floralwhite",
    "forestgreen",
    "fuchsia",
    "gainsboro",
    "ghostwhite",
    "gold",
    "goldenrod",
    "gray",
    "green",
    "greenyellow",
    "grey",
    "honeydew",
    "hotpink",
    "indianred",
    "indigo",
    "ivory",
    "khaki",
    "lavender",
    "lavenderblush",
    "lawngreen",
    "lemonchiffon",
    "lightblue",
    "lightcoral",
    "lightcyan",
    "lightgoldenrodyellow",
    "lightgray",
    "lightgreen",
    "lightgrey",
    "lightpink",
    "lightsalmon",
    "lightseagreen",
    "lightskyblue",
    "lightslategray",
    "lightslategrey",
    "lightsteelblue",
    "lightyellow",
    "lime",
    "limegreen",
    "linen",
    "magenta",
    "maroon",
    "mediumaquamarine",
    "mediumblue",
    "mediumorchid",
    "mediumpurple",
    "mediumseagreen",
    "mediumslateblue",
    "mediumspringgreen",
    "mediumturquoise",
    "mediumvioletred",
    "midnightblue",
    "mintcream",
    "mistyrose",
    "moccasin",
    "navajowhite",
    "navy",
    "oldlace",
    "olive",
    "olivedrab",
    "orange",
    "orangered",
    "orchid",
    "palegoldenrod",
    "palegreen",
    "paleturquoise",
    "palevioletred",
    "papayawhip",
    "peachpuff",
    "peru",
    "pink",
    "plum",
    "powderblue",
    "purple",
    "rebeccapurple",
    "red",
    "rosybrown",
    "royalblue",
    "saddlebrown",
    "salmon",
    "sandybrown",
    "seagreen",
    "seashell",
    "sienna",
    "silver",
    "skyblue",
    "slateblue",
    "slategray",
    "slategrey",
    "snow",
    "springgreen",
    "steelblue",
    "tan",
    "teal",
    "thistle",
    "tomato",
    "turquoise",
    "violet",
    "wheat",
    "white",
    "whitesmoke",
    "yellow",
    "yellowgreen",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn css(input: &str) -> Result<String, String> {
        parse(input).map(|d| to_css(&d))
    }

    #[test]
    fn named_colors_are_sorted_for_binary_search() {
        assert!(NAMED_COLORS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn accepts_a_plain_theme() {
        let theme = css("--pico-primary: #7b3fe4;\n--pico-border-radius: 0.5rem;").unwrap();
        assert_eq!(
            theme,
            "--pico-primary: #7b3fe4;\n--pico-border-radius: 0.5rem;\n"
        );
    }

    #[test]
    fn accepts_every_documented_color_form() {
        for value in [
            "#fff",
            "#ffff",
            "#7b3fe4",
            "#7b3fe4cc",
            "rgb(123 63 228)",
            "rgba(123, 63, 228, 0.5)",
            "hsl(262 76% 57%)",
            "oklch(62.8% 0.258 29.23)",
            "rebeccapurple",
            "transparent",
            "currentcolor",
        ] {
            assert!(
                parse(&format!("--pico-primary: {value};")).is_ok(),
                "{value} should be a colour"
            );
        }
    }

    #[test]
    fn accepts_hex_named_and_functional_color_pairs() {
        for value in [
            "light-dark(#7b3fe4, #a982ff)",
            "light-dark(white, rebeccapurple)",
            "light-dark(transparent, currentcolor)",
            "light-dark(rgb(250 248 255), rgb(24 18 32))",
            "light-dark(rgba(250, 248, 255, 0.9), hsl(267 100% 75%))",
            "light-dark(oklch(98% 0.02 295), oklch(20% 0.04 295))",
        ] {
            assert!(
                parse(&format!("--pico-primary: {value};")).is_ok(),
                "{value} should be a light/dark colour pair"
            );
        }
    }

    #[test]
    fn a_color_pair_has_canonical_whitespace_and_round_trips() {
        let source = "\n --devsite-scheme:   auto;\n --pico-primary:\n   light-dark(  #7b3fe4  ,   rgb( 169  130  255 )  );\n";
        let canonical = css(source).unwrap();
        assert_eq!(
            canonical,
            "--devsite-scheme: auto;\n--pico-primary: light-dark( #7b3fe4 , rgb( 169 130 255 ) );\n"
        );
        assert_eq!(css(&canonical).unwrap(), canonical);
    }

    #[test]
    fn damis_palette_can_define_both_schemes() {
        let source = "
            --devsite-scheme: auto;
            --pico-background-color: light-dark(#fefae0, #283618);
            --pico-color: light-dark(#283618, #fefae0);
            --pico-primary: light-dark(#bc6c25, #dda15e);
            --pico-accordion-active-summary-color: light-dark(#606c38, #dda15e);
            --pico-accordion-close-summary-color: light-dark(#606c38, #dda15e);
            --pico-accordion-open-summary-color: light-dark(#606c38, #dda15e);
            --pico-box-shadow: unset;
        ";
        assert_eq!(
            css(source).unwrap(),
            "--devsite-scheme: auto;\n\
             --pico-background-color: light-dark(#fefae0, #283618);\n\
             --pico-color: light-dark(#283618, #fefae0);\n\
             --pico-primary: light-dark(#bc6c25, #dda15e);\n\
             --pico-accordion-active-summary-color: light-dark(#606c38, #dda15e);\n\
             --pico-accordion-close-summary-color: light-dark(#606c38, #dda15e);\n\
             --pico-accordion-open-summary-color: light-dark(#606c38, #dda15e);\n\
             --pico-box-shadow: unset;\n"
        );
    }

    #[test]
    fn box_shadow_can_only_be_removed() {
        assert!(parse("--pico-box-shadow: unset;").is_ok());
        for value in ["none", "0 0 1rem red", "var(--shadow)"] {
            assert!(
                parse(&format!("--pico-box-shadow: {value};")).is_err(),
                "{value} should be refused"
            );
        }
    }

    #[test]
    fn color_pairs_are_accepted_with_forced_and_automatic_schemes() {
        for scheme in ["light", "dark", "auto"] {
            let theme = format!(
                "--devsite-scheme: {scheme}; \
                 --pico-primary: light-dark(#7b3fe4, #a982ff);"
            );
            assert!(
                parse(&theme).is_ok(),
                "{scheme} should accept a colour pair"
            );
        }
    }

    #[test]
    fn rejects_malformed_color_pairs() {
        for value in [
            "light-dark()",
            "light-dark(red)",
            "light-dark(, blue)",
            "light-dark(red, )",
            "light-dark(red, blue, green)",
            "light-dark(red,, blue)",
            "light-dark(rgb(1 2 3), blue",
            "light-dark(rgb(1 2 3, blue)",
            "light-dark(rgb(1 2 3)), blue)",
        ] {
            assert!(
                parse(&format!("--pico-primary: {value};")).is_err(),
                "{value} should be refused"
            );
        }
    }

    #[test]
    fn rejects_unsupported_functions_inside_color_pairs() {
        for value in [
            "light-dark(var(--pico-color), blue)",
            "light-dark(calc(1 + 1), blue)",
            "light-dark(url(https://example.com/x.png), blue)",
            "light-dark(linear-gradient(red, blue), green)",
            "light-dark(light-dark(red, blue), green)",
            "light-dark(rgb(calc(1 + 1) 0 0), blue)",
        ] {
            assert!(
                parse(&format!("--pico-primary: {value};")).is_err(),
                "{value} should be refused"
            );
        }
    }

    #[test]
    fn rejects_values_that_only_look_like_colors() {
        for value in [
            "url(https://example.com/x.png)",
            "var(--pico-color)",
            "rgb(calc(1 + 1) 0 0)",
            "#12345",
            "#gggggg",
            "notacolour",
            "rgb(1 2 3 4 5)",
        ] {
            assert!(
                parse(&format!("--pico-primary: {value};")).is_err(),
                "{value} should be refused"
            );
        }
    }

    #[test]
    fn rejects_anything_that_is_not_a_declaration() {
        // The whole point of the whitelist: a theme cannot become a stylesheet.
        for source in [
            "body { display: none }",
            "--pico-primary: red } body { position: fixed",
            "@import url(evil.css);",
            "--pico-primary: red !important;",
            "</style><script>alert(1)</script>",
            "--pico-primary: red; /* unterminated",
            "--pico-primary: light-dark(red, blue); } body { display: none",
            "--pico-primary: light-dark(red, </style><script>alert(1)</script>);",
        ] {
            assert!(parse(source).is_err(), "{source:?} should be refused");
        }
    }

    #[test]
    fn reported_color_grammar_includes_color_pairs() {
        let description = properties()
            .find(|(name, _)| *name == "--pico-primary")
            .unwrap()
            .1;
        assert!(description.contains("light-dark(#7b3fe4, #a982ff)"));
    }

    #[test]
    fn rejects_properties_outside_the_table() {
        // Real CSS properties are refused as firmly as invented ones: a theme
        // may only assign the variables the template is built out of.
        for property in ["position", "display", "--pico-icon-close", "--anything"] {
            assert!(
                parse(&format!("{property}: none;")).is_err(),
                "{property} should be refused"
            );
        }
    }

    #[test]
    fn suggests_the_nearest_property_on_a_typo() {
        let error = parse("--pico-primary-color: red;").unwrap_err();
        assert!(error.contains("--pico-primary"), "unhelpful error: {error}");
    }

    #[test]
    fn the_typeface_is_not_negotiable() {
        assert!(parse("--pico-font-family: Comic Sans MS;").is_err());
        assert!(parse("--pico-font-weight: 400;").is_ok());
        assert!(parse("--pico-font-weight: 700;").is_ok());
        // Open Sans is vendored at exactly two weights; anything else would be
        // rounded to one of them anyway, so say so rather than pretend.
        assert!(parse("--pico-font-weight: 600;").is_err());
    }

    #[test]
    fn lengths_need_a_unit_and_numbers_must_not_have_one() {
        assert!(parse("--pico-border-radius: 0;").is_ok());
        assert!(parse("--pico-border-radius: 0.5rem;").is_ok());
        assert!(parse("--pico-border-radius: 8;").is_err());
        assert!(parse("--pico-border-radius: -1rem;").is_err());
        assert!(parse("--pico-line-height: 1.5;").is_ok());
        assert!(parse("--pico-line-height: 1.5rem;").is_err());
    }

    #[test]
    fn comments_and_spacing_survive_normalisation() {
        let theme = css("/* my colours */\n  --pico-primary  :   rgb( 1 , 2 , 3 )  ;\n").unwrap();
        assert_eq!(theme, "--pico-primary: rgb( 1 , 2 , 3 );\n");
    }

    #[test]
    fn a_comment_cannot_glue_two_tokens_together() {
        // `--pico/**/-primary` must not become a valid property name.
        assert!(parse("--pico/**/-primary: red;").is_err());
    }

    #[test]
    fn the_last_assignment_wins_without_reordering() {
        let theme = css("--pico-primary: red; --pico-color: blue; --pico-primary: green;").unwrap();
        assert_eq!(theme, "--pico-primary: green;\n--pico-color: blue;\n");
    }

    #[test]
    fn validated_output_is_safe_to_inline_in_a_style_element() {
        // Not a claim about escaping — a claim about the alphabet. Whatever
        // survives parsing cannot contain a character that ends a style block.
        let source = "--pico-primary: #abc; --pico-spacing: 1rem; --devsite-scheme: dark;";
        for declaration in parse(source).unwrap() {
            assert!(declaration
                .value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"#%.,/()+- ".contains(&b)));
        }
    }

    #[test]
    fn oversized_input_is_refused_before_parsing() {
        let huge = "--pico-primary: red;".repeat(MAX_INPUT);
        assert!(parse(&huge).is_err());
    }

    #[test]
    fn an_empty_theme_is_valid_and_empty() {
        assert_eq!(parse("").unwrap(), vec![]);
        assert_eq!(parse("  \n /* nothing */ ;;; ").unwrap(), vec![]);
    }
}
