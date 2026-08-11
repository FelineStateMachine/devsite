//! `devsite` — configure a profile and expose local services.

mod client;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use devsite_daemon::config::{validate_origin, DaemonConfig, ExposedResource, Paths, Visibility};
use devsite_daemon::Daemon;
use serde::Deserialize;
use std::sync::Arc;
use url::Url;

use crate::client::ControlPlane;

#[derive(Parser)]
#[command(name = "devsite", about = "Share public work and reach your local services")]
struct Cli {
    /// Control plane base URL.
    #[arg(long, env = "DEVSITE_SERVER", default_value = "https://dev.site", global = true)]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store a session token from the website and pin the control plane's signing key.
    Login {
        /// Session token shown by the website after signing in.
        #[arg(long)]
        token: Option<String>,
    },
    /// Profile management.
    #[command(subcommand)]
    Profile(ProfileCommand),
    /// Add an ordinary external link.
    #[command(subcommand)]
    Link(LinkCommand),
    /// Expose a local service.
    Expose {
        /// Local origin, e.g. http://127.0.0.1:4101
        origin: Url,
        #[arg(long)]
        name: String,
        #[arg(long, conflicts_with_all = ["private", "share"])]
        public: bool,
        #[arg(long, conflicts_with_all = ["public", "share"])]
        private: bool,
        /// Share with a specific user, e.g. --share @frank. Repeatable.
        #[arg(long, value_name = "@handle")]
        share: Vec<String>,
    },
    /// Profile appearance.
    #[command(subcommand)]
    Theme(ThemeCommand),
    /// Show what this machine is configured to serve.
    Status,
    /// Daemon control.
    #[command(subcommand)]
    Daemon(DaemonCommand),
}

#[derive(Subcommand)]
enum ProfileCommand {
    /// Claim a handle, e.g. `devsite profile create @dami`.
    Create { handle: String },
}

#[derive(Subcommand)]
enum LinkCommand {
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        url: String,
        #[arg(long)]
        public: bool,
    },
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Run the daemon in the foreground.
    Run,
}

/// A theme is a list of `--pico-*` declarations, checked by the control plane
/// against a fixed whitelist. There is no theme dropdown, and no arbitrary CSS.
#[derive(Subcommand)]
enum ThemeCommand {
    /// Print the theme currently applied to your profile.
    Show,
    /// Replace your theme with declarations read from a file, or `-` for stdin.
    Set { file: String },
    /// Remove your theme and go back to the defaults.
    Clear,
    /// List every property a theme may set, and what each one accepts.
    Properties,
}

#[derive(Deserialize)]
struct ThemeResponse {
    css: String,
}

#[derive(Deserialize)]
struct ThemeProperties {
    properties: Vec<ThemeProperty>,
}

#[derive(Deserialize)]
struct ThemeProperty {
    name: String,
    accepts: String,
}

#[derive(Deserialize)]
struct PubKeyResponse {
    public_key: String,
}

#[derive(Deserialize)]
struct HandleResponse {
    handle: String,
}

#[derive(Deserialize)]
struct CreateResourceResponse {
    resource_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "devsite=info,devsite_daemon=info,warn".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let paths = Paths::discover()?;

    match cli.command {
        Command::Login { token } => login(&paths, &cli.server, token).await,
        Command::Profile(ProfileCommand::Create { handle }) => {
            create_profile(&paths, &cli.server, &handle).await
        }
        Command::Link(LinkCommand::Add { name, url, public }) => {
            add_link(&paths, &cli.server, &name, &url, public).await
        }
        Command::Expose {
            origin,
            name,
            public,
            private,
            share,
        } => expose(&paths, &cli.server, origin, &name, public, private, share).await,
        Command::Theme(command) => theme(&paths, &cli.server, command).await,
        Command::Status => status(&paths),
        Command::Daemon(DaemonCommand::Run) => run_daemon(&paths, &cli.server).await,
    }
}

fn load_authenticated(paths: &Paths) -> Result<DaemonConfig> {
    let config = paths.load_config()?;
    if config.session_token.is_none() {
        bail!("not signed in — run `devsite login` first");
    }
    Ok(config)
}

async fn login(paths: &Paths, server: &str, token: Option<String>) -> Result<()> {
    let token = match token {
        Some(token) => token,
        None => {
            println!("Sign in at {server} and paste the session token shown there.");
            print!("token: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };
    if token.is_empty() {
        bail!("no token provided");
    }

    let api = ControlPlane::new(server, Some(token.clone()));
    // Confirm the token works before storing it, so a typo fails here rather than at the
    // first API call.
    let me: serde_json::Value = api
        .get("/api/me")
        .await
        .context("that token was not accepted")?;
    let pubkey: PubKeyResponse = api.get("/api/pubkey").await?;

    let mut config = paths.load_config()?;
    config.server_url = Some(server.trim_end_matches('/').to_string());
    config.session_token = Some(token);
    // Pinned now, and every capability is checked against it from here on.
    config.control_plane_key = Some(pubkey.public_key);
    paths.save_config(&config)?;

    let handle = me
        .get("handle")
        .and_then(|h| h.as_str())
        .unwrap_or("(no handle yet)");
    println!("signed in as {handle}");
    println!("pinned control plane key {}", config.control_plane_key.unwrap());
    Ok(())
}

async fn create_profile(paths: &Paths, server: &str, handle: &str) -> Result<()> {
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.session_token.clone());
    let response: HandleResponse = api
        .post(
            "/api/profile",
            &serde_json::json!({ "handle": handle.trim_start_matches('@') }),
        )
        .await?;
    println!("profile ready at {server}/@{}", response.handle);
    Ok(())
}

async fn add_link(paths: &Paths, server: &str, name: &str, url: &str, public: bool) -> Result<()> {
    if !public {
        bail!("links are external URLs and are always public; pass --public to confirm");
    }
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.session_token.clone());
    let _: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": name,
                "kind": "link",
                "visibility": "public",
                "url": url,
            }),
        )
        .await?;
    println!("added link {name} → {url}");
    Ok(())
}

async fn expose(
    paths: &Paths,
    server: &str,
    origin: Url,
    name: &str,
    public: bool,
    private: bool,
    share: Vec<String>,
) -> Result<()> {
    // Refuse to proxy to the public internet: dev.site exposes local services, and an
    // arbitrary upstream would make the daemon a traffic launderer.
    validate_origin(&origin)?;

    let visibility = match (public, private, share.is_empty()) {
        (true, false, true) => Visibility::Public,
        (false, _, true) => Visibility::Private,
        (false, false, false) => Visibility::Shared,
        (true, _, false) => bail!("--public and --share are mutually exclusive"),
        _ => bail!("choose one of --public, --private or --share"),
    };

    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.session_token.clone());

    let response: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": name,
                "kind": "service",
                "visibility": visibility_str(visibility),
                // Deliberately absent: the local origin never leaves this machine.
                "share_with": share.iter().map(|h| h.trim_start_matches('@')).collect::<Vec<_>>(),
            }),
        )
        .await?;

    let resource_id = response
        .resource_id
        .parse()
        .context("the server returned an unusable resource id")?;

    let mut config = paths.load_config()?;
    config.resources.retain(|r| r.name != name);
    config.resources.push(ExposedResource {
        resource_id,
        name: name.to_string(),
        origin: origin.clone(),
        visibility,
    });
    paths.save_config(&config)?;

    println!("exposed {name} → {origin} ({})", visibility_str(visibility));
    if !share.is_empty() {
        println!("  shared with {}", share.join(", "));
    }
    println!("  resource id {resource_id}");
    println!("\nrun `devsite daemon run` to serve it.");
    Ok(())
}

async fn theme(paths: &Paths, server: &str, command: ThemeCommand) -> Result<()> {
    // The property list is public: it is the documentation, and it comes from
    // the binary that enforces it rather than from a copy kept here.
    if let ThemeCommand::Properties = command {
        let api = ControlPlane::new(server, None);
        let listing: ThemeProperties = api.get("/api/theme/properties").await?;
        for property in listing.properties {
            println!("{:<44} {}", property.name, property.accepts);
        }
        return Ok(());
    }

    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.session_token.clone());

    match command {
        ThemeCommand::Properties => unreachable!("handled above, before authentication"),
        ThemeCommand::Show => {
            let theme: ThemeResponse = api.get("/api/theme").await?;
            if theme.css.trim().is_empty() {
                println!("no theme set — run `devsite theme set <file>`");
            } else {
                print!("{}", theme.css);
            }
        }
        ThemeCommand::Set { file } => {
            let css = if file == "-" {
                std::io::read_to_string(std::io::stdin())?
            } else {
                std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?
            };
            // The server is the only validator. Rejections arrive as its own
            // message — "`--pico-primary: wine` — expected a colour, e.g. …" —
            // and are printed as-is rather than re-worded here.
            let saved: ThemeResponse = api.put("/api/theme", &serde_json::json!({ "css": css })).await?;
            print!("{}", saved.css);
            println!("theme saved");
        }
        ThemeCommand::Clear => {
            let _: ThemeResponse = api.put("/api/theme", &serde_json::json!({ "css": "" })).await?;
            println!("theme cleared");
        }
    }
    Ok(())
}

fn visibility_str(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
        Visibility::Shared => "shared",
    }
}

fn status(paths: &Paths) -> Result<()> {
    let config = paths.load_config()?;
    println!("config      {}", paths.config().display());
    println!("identity    {}", paths.identity().display());
    println!(
        "server      {}",
        config.server_url.as_deref().unwrap_or("(not signed in)")
    );
    println!(
        "signing key {}",
        config.control_plane_key.as_deref().unwrap_or("(not pinned)")
    );

    if config.resources.is_empty() {
        println!("\nno services exposed yet");
        return Ok(());
    }
    println!("\nexposed services:");
    for resource in &config.resources {
        println!(
            "  {:<16} {:<10} {}",
            resource.name,
            visibility_str(resource.visibility),
            resource.origin
        );
    }
    Ok(())
}

async fn run_daemon(paths: &Paths, server: &str) -> Result<()> {
    let config = load_authenticated(paths)?;
    let server_url = config.server_url.clone().unwrap_or_else(|| server.to_string());
    let token = config.session_token.clone();

    let secret_key = paths.load_or_create_identity()?;
    let daemon = Arc::new(Daemon::bind(secret_key, config).await?);

    let endpoint_id = daemon.endpoint().id().to_string();
    let relay = daemon
        .endpoint()
        .addr()
        .relay_urls()
        .next()
        .map(|u| u.to_string())
        .context("no relay was assigned; check network connectivity")?;

    println!("daemon online");
    println!("  endpoint {endpoint_id}");
    println!("  relay    {relay}");

    // Told to the control plane once, not on a timer.
    //
    // The endpoint id is the public half of the key in DEVSITE_HOME/identity, so
    // it is the same on every run and there is nothing to refresh. The relay
    // above is printed for the operator and deliberately not uploaded: the
    // endpoint publishes its own address through iroh's address lookup, and
    // viewers resolve it from there. The control plane holds permissions; it is
    // not a directory service.
    let api = ControlPlane::new(&server_url, token);
    api.put_empty(
        "/api/daemon",
        &serde_json::json!({ "endpoint_id": endpoint_id }),
    )
    .await
    .context("registering this daemon with the control plane")?;

    tokio::select! {
        result = Arc::clone(&daemon).serve() => result?,
        _ = tokio::signal::ctrl_c() => println!("\nshutting down"),
    }
    Ok(())
}
