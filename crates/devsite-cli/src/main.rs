//! `devsite` — configure a profile and expose local services.

mod client;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use devsite_client::{ServiceStream, ViewerEndpoint};
use devsite_daemon::config::{DaemonConfig, ExposedResource, Paths, Visibility};
use devsite_daemon::Daemon;
use devsite_proto::SignedCapability;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::ControlPlane;

#[derive(Parser)]
#[command(
    name = "devsite",
    version,
    about = "Share public work and reach your local services"
)]
struct Cli {
    /// Control plane base URL.
    #[arg(
        long,
        env = "DEVSITE_SERVER",
        default_value = "https://dev.site",
        global = true
    )]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Store a session token from the website and pin the control plane's signing key.
    Login {
        /// Session token shown by the website after signing in.
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
        /// Local TCP port on 127.0.0.1.
        port: u16,
        /// Presentation name. Defaults to `port PORT`.
        #[arg(long)]
        name: Option<String>,
        /// Invite a specific user to accept the share, e.g. --share @bob. Repeatable.
        #[arg(long, value_name = "@handle")]
        share: Vec<String>,
        /// Presentation folder. TCP services default to `Services`.
        #[arg(long, value_name = "NAME")]
        folder: Option<String>,
    },
    /// Forward a local TCP port to a service you may access.
    Connect {
        /// Short-lived connection ticket minted on dev.site.
        ticket: String,
        /// Local address to listen on. Port 0 chooses a free port.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
    },
    /// Stop exposing a local service and take it off your profile.
    Unexpose {
        /// The name it was exposed under.
        name: String,
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
    /// Claim a handle, e.g. `devsite profile create @alice`.
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
        /// File it under a folder on your profile. Leaving it off takes it out of
        /// whatever folder it was in.
        #[arg(long, value_name = "NAME")]
        folder: Option<String>,
    },
    /// Take a link off your profile. Re-running `add` with the same name edits
    /// it in place; this is for when it should not be there at all.
    Remove { name: String },
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
struct PublicConfig {
    api_version: u32,
    minimum_cli_version: String,
}

#[derive(Deserialize)]
struct HandleResponse {
    handle: String,
}

#[derive(Deserialize)]
struct CreateResourceResponse {
    resource_id: String,
}

#[derive(Deserialize)]
struct CapabilityResponse {
    capability: String,
    daemon_endpoint_id: String,
}

#[derive(Deserialize)]
struct RedeemTicketResponse {
    session_token: String,
    resource_id: String,
    name: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct ResourceListing {
    resources: Vec<Resource>,
}

#[derive(Deserialize)]
struct Resource {
    resource_id: String,
    name: String,
    kind: String,
    /// Set for links only; a service's target never leaves the machine serving it.
    url: Option<String>,
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
        Command::Link(LinkCommand::Add {
            name,
            url,
            public,
            folder,
        }) => add_link(&paths, &cli.server, &name, &url, public, folder).await,
        Command::Link(LinkCommand::Remove { name }) => {
            remove_link(&paths, &cli.server, &name).await
        }
        Command::Unexpose { name } => unexpose(&paths, &cli.server, &name).await,
        Command::Expose {
            port,
            name,
            share,
            folder,
        } => expose(&paths, &cli.server, port, name, share, folder).await,
        Command::Connect { ticket, listen } => connect(&cli.server, &ticket, listen).await,
        Command::Theme(command) => theme(&paths, &cli.server, command).await,
        Command::Status => status(&paths),
        Command::Daemon(DaemonCommand::Run) => run_daemon(&paths, &cli.server).await,
    }
}

fn load_authenticated(paths: &Paths) -> Result<DaemonConfig> {
    let config = paths.load_config()?;
    if config.machine_credential.is_none() {
        bail!("not signed in — run `devsite login` first");
    }
    Ok(config)
}

async fn login(paths: &Paths, server: &str, token: Option<String>) -> Result<()> {
    let token = match token {
        Some(token) => token,
        None => {
            println!("Open {server}, create a machine credential, and paste it here.");
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
    let server_config: PublicConfig = api.get("/api/config").await?;
    if server_config.api_version != 2 {
        bail!(
            "this CLI speaks API version 2, but the server reports version {}",
            server_config.api_version
        );
    }
    // Confirm the credential works before storing it, so a typo fails here
    // rather than at the first API call.
    let me: serde_json::Value = api
        .get("/api/me")
        .await
        .context("that token was not accepted")?;
    let pubkey: PubKeyResponse = api.get("/api/pubkey").await?;

    let mut config = paths.load_config()?;
    config.server_url = Some(server.trim_end_matches('/').to_string());
    config.machine_credential = Some(token);
    // Pinned now, and every capability is checked against it from here on.
    config.control_plane_key = Some(pubkey.public_key);
    paths.save_config(&config)?;

    let handle = me
        .get("handle")
        .and_then(|h| h.as_str())
        .unwrap_or("(no handle yet)");
    println!("signed in as {handle}");
    println!(
        "server requires CLI {} or newer",
        server_config.minimum_cli_version
    );
    println!(
        "pinned control plane key {}",
        config.control_plane_key.unwrap()
    );
    Ok(())
}

async fn create_profile(paths: &Paths, server: &str, handle: &str) -> Result<()> {
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let response: HandleResponse = api
        .post(
            "/api/profile",
            &serde_json::json!({ "handle": handle.trim_start_matches('@') }),
        )
        .await?;
    println!("profile ready at {server}/@{}", response.handle);
    Ok(())
}

async fn add_link(
    paths: &Paths,
    server: &str,
    name: &str,
    url: &str,
    public: bool,
    folder: Option<String>,
) -> Result<()> {
    if !public {
        bail!("links are external URLs and are always public; pass --public to confirm");
    }
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let _: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": name,
                "kind": "link",
                "visibility": "public",
                "url": url,
                "folder": folder,
            }),
        )
        .await?;
    println!("added link {name} → {url}");
    if let Some(folder) = &folder {
        println!("  in {folder}");
    }
    Ok(())
}

/// Delete one of your resources, found by the name you gave it.
///
/// Names are resolved here rather than server-side because the server keys
/// everything by id, and an endpoint that deleted by name would have to invent a
/// rule for a link and a service sharing one. Listing first also means the "no
/// such thing" case is answered with the names that do exist.
async fn remove_resource(paths: &Paths, server: &str, name: &str, kind: &str) -> Result<Resource> {
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());

    let listing: ResourceListing = api.get("/api/resources").await?;
    let found = listing
        .resources
        .into_iter()
        .find(|r| r.name == name && r.kind == kind);

    let Some(resource) = found else {
        bail!("you have no {kind} called `{name}`");
    };
    api.delete(&format!("/api/resources/{}", resource.resource_id))
        .await?;
    Ok(resource)
}

async fn remove_link(paths: &Paths, server: &str, name: &str) -> Result<()> {
    let removed = remove_resource(paths, server, name, "link").await?;
    println!("removed link {name} → {}", removed.url.unwrap_or_default());
    Ok(())
}

/// Stop serving a local service and take it off the profile.
///
/// Both halves matter and in this order: the control plane forgets it, then this
/// machine does. A daemon that kept serving a resource the control plane has
/// deleted is harmless — no capability can be issued for it any more — but a
/// config that still lists it would re-register the name on the next `expose`.
async fn unexpose(paths: &Paths, server: &str, name: &str) -> Result<()> {
    remove_resource(paths, server, name, "service").await?;

    let mut config = paths.load_config()?;
    let before = config.resources.len();
    config.resources.retain(|r| r.name != name);
    paths.save_config(&config)?;

    println!("unexposed {name}");
    if config.resources.len() == before {
        println!("  (this machine was not serving it; removed from your profile)");
    } else {
        println!("  a running daemon will stop serving it automatically");
    }
    Ok(())
}

async fn expose(
    paths: &Paths,
    server: &str,
    port: u16,
    name: Option<String>,
    share: Vec<String>,
    folder: Option<String>,
) -> Result<()> {
    if port == 0 {
        bail!("port 0 cannot be exposed");
    }
    let name = name.unwrap_or_else(|| format!("port {port}"));
    let folder = Some(folder.unwrap_or_else(|| "Services".to_string()));
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let visibility = if share.is_empty() {
        Visibility::Private
    } else {
        Visibility::Shared
    };

    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());

    let response: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": &name,
                "kind": "service",
                "visibility": visibility_str(visibility),
                // Deliberately absent: the local target never leaves this machine.
                "share_with": share.iter().map(|h| h.trim_start_matches('@')).collect::<Vec<_>>(),
                "folder": folder,
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
        name: name.clone(),
        target,
        visibility,
    });
    paths.save_config(&config)?;

    println!("exposed {name} → {target} ({})", visibility_str(visibility));
    if let Some(folder) = &folder {
        println!("  in {folder}");
    }
    if !share.is_empty() {
        println!("  invited {}", share.join(", "));
    }
    println!("  {server}/s/{resource_id}");
    println!("\nrun `devsite daemon run` to serve it; an existing daemon reloads automatically.");
    Ok(())
}

async fn connect(server: &str, ticket: &str, listen: SocketAddr) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("--listen must be a loopback address; refusing to publish the tunnel on the LAN");
    }
    let viewer = Arc::new(ViewerEndpoint::create().await?);
    let bootstrap = ControlPlane::new(server, None);
    let redeemed: RedeemTicketResponse = bootstrap
        .post(
            "/api/tickets/redeem",
            &serde_json::json!({
                "ticket": ticket,
                "client_endpoint_id": viewer.endpoint_id().to_string(),
            }),
        )
        .await
        .context("redeeming connection ticket")?;
    let api = Arc::new(ControlPlane::new(server, Some(redeemed.session_token)));
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding local listener {listen}"))?;
    let bound = listener.local_addr()?;

    println!(
        "connected to {} ({server}/s/{})",
        redeemed.name, redeemed.resource_id
    );
    println!("  listening on {bound}");
    println!("  session expires at unix time {}", redeemed.expires_at);
    println!("  press Ctrl-C to stop");

    loop {
        let (local, peer) = tokio::select! {
            accepted = listener.accept() => accepted.context("accepting local connection")?,
            _ = tokio::signal::ctrl_c() => {
                println!("\nshutting down");
                if let Err(err) = api.delete("/api/tunnel/session").await {
                    tracing::warn!("could not revoke tunnel session during shutdown: {err:#}");
                }
                viewer.close().await;
                return Ok(());
            }
        };
        let api = Arc::clone(&api);
        let viewer = Arc::clone(&viewer);
        tokio::spawn(async move {
            if let Err(err) = forward_connection(&api, &viewer, local).await {
                tracing::warn!(%peer, "service connection failed: {err:#}");
            }
        });
    }
}

async fn forward_connection(
    api: &ControlPlane,
    viewer: &ViewerEndpoint,
    local: TcpStream,
) -> Result<()> {
    let grant: CapabilityResponse = api
        .post("/api/tunnel/capability", &serde_json::json!({}))
        .await?;
    let raw = data_encoding::BASE64URL_NOPAD
        .decode(grant.capability.as_bytes())
        .context("the server returned a malformed capability")?;
    let capability =
        SignedCapability::from_bytes(&raw).context("the server returned a malformed capability")?;
    let daemon: iroh::EndpointId = grant
        .daemon_endpoint_id
        .parse()
        .context("the server returned an invalid daemon endpoint")?;
    let ServiceStream { mut send, mut recv } = viewer.connect(daemon, capability).await?;
    let (mut local_read, mut local_write) = local.into_split();

    let local_to_service = async {
        copy(&mut local_read, &mut send).await?;
        send.finish().context("finishing service input")?;
        Ok::<_, anyhow::Error>(())
    };
    let service_to_local = async {
        copy(&mut recv, &mut local_write).await?;
        local_write.shutdown().await.ok();
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(local_to_service, service_to_local)?;
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
    let api = ControlPlane::new(server, config.machine_credential.clone());

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
            let saved: ThemeResponse = api
                .put("/api/theme", &serde_json::json!({ "css": css }))
                .await?;
            print!("{}", saved.css);
            println!("theme saved");
        }
        ThemeCommand::Clear => {
            let _: ThemeResponse = api
                .put("/api/theme", &serde_json::json!({ "css": "" }))
                .await?;
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
        config
            .control_plane_key
            .as_deref()
            .unwrap_or("(not pinned)")
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
            resource.target
        );
    }
    Ok(())
}

async fn run_daemon(paths: &Paths, server: &str) -> Result<()> {
    let config = load_authenticated(paths)?;
    let server_url = config
        .server_url
        .clone()
        .unwrap_or_else(|| server.to_string());
    let token = config.machine_credential.clone();

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

    let reload_paths = Paths {
        root: paths.root.clone(),
    };
    tokio::select! {
        result = Arc::clone(&daemon).serve() => result?,
        result = reload_config(reload_paths, Arc::clone(&daemon)) => result?,
        _ = tokio::signal::ctrl_c() => println!("\nshutting down"),
    }
    daemon.close().await;
    Ok(())
}

async fn reload_config(paths: Paths, daemon: Arc<Daemon>) -> Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_error = None;
    // The initial config was loaded immediately before the daemon started; the
    // first useful tick is the next one.
    interval.tick().await;
    loop {
        interval.tick().await;
        match paths.load_config() {
            Ok(config) => {
                last_error = None;
                if daemon.replace_resources(config.resources).await {
                    println!("reloaded exposed services");
                }
            }
            Err(err) => {
                let message = format!("{err:#}");
                if last_error.as_deref() != Some(message.as_str()) {
                    tracing::warn!("could not reload daemon config: {message}");
                    last_error = Some(message);
                }
            }
        }
    }
}
