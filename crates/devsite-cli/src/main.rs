//! `devsite` — configure a profile and host local services.

mod client;

use anyhow::{bail, Context, Result};
use clap::{error::ErrorKind, Parser, Subcommand};
use devsite_client::{ServiceStream, ViewerEndpoint};
use devsite_daemon::config::{DaemonConfig, HostedService, Paths, Visibility};
use devsite_daemon::Daemon;
use devsite_proto::SignedCapability;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::ControlPlane;

#[derive(Parser)]
#[command(
    name = "devsite",
    version,
    about = "Share public work and reach your local services",
    after_help = "Typical workflows:\n  devsite login dsm_...\n  devsite link set --name docs --url https://example.com --public\n  devsite service host 3000 --name app\n  devsite connect dst_...\n\nUse `devsite <command> --help` for command-specific arguments."
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

    /// Emit stable JSON on stdout. Resident commands emit newline-delimited events.
    #[arg(long, global = true)]
    json: bool,

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
    /// Manage ordinary external links.
    #[command(subcommand)]
    Link(LinkCommand),
    /// Host local TCP services.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Forward a local TCP port to a service you may access.
    Connect {
        /// Short-lived connection ticket minted on dev.site.
        ticket: String,
        /// Local address to listen on. Port 0 chooses a free port.
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
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
enum LinkCommand {
    /// Create or replace a named link.
    Set {
        /// Stable presentation name used to identify later updates and removal.
        #[arg(long)]
        name: String,
        /// HTTP(S) destination without embedded credentials.
        #[arg(long)]
        url: String,
        /// Make the link visible to everyone. Without this or --share it is private.
        #[arg(long, conflicts_with = "share")]
        public: bool,
        /// Invite a specific user to accept the link. Repeatable.
        #[arg(long, value_name = "@handle")]
        share: Vec<String>,
        /// File it under a folder on your profile. Leaving it off takes it out of
        /// whatever folder it was in.
        #[arg(long, value_name = "NAME")]
        folder: Option<String>,
    },
    /// Take a link off your profile.
    Remove {
        /// Name previously passed to `link set`.
        name: String,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Host a loopback TCP port as a named service.
    Host {
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
    /// Stop hosting a service and take it off your profile.
    Remove {
        /// Name previously passed to `service host`.
        name: String,
    },
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Run the daemon in the foreground.
    Run,
    /// Report whether a daemon is serving this machine's config.
    Status,
}

/// A theme is a list of `--pico-*` declarations, checked by the control plane
/// against a fixed whitelist. There is no theme dropdown, and no arbitrary CSS.
#[derive(Subcommand)]
enum ThemeCommand {
    /// Print the theme currently applied to your profile.
    Show,
    /// Replace your theme with declarations read from a file, or `-` for stdin.
    Set {
        /// CSS declaration file, or `-` to read stdin.
        file: String,
    },
    /// Remove your theme and go back to the defaults.
    Clear,
    /// List every property a theme may set, and what each one accepts.
    Properties,
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "login",
            Self::Link(LinkCommand::Set { .. }) => "link.set",
            Self::Link(LinkCommand::Remove { .. }) => "link.remove",
            Self::Service(ServiceCommand::Host { .. }) => "service.host",
            Self::Service(ServiceCommand::Remove { .. }) => "service.remove",
            Self::Connect { .. } => "connect",
            Self::Theme(ThemeCommand::Show) => "theme.show",
            Self::Theme(ThemeCommand::Set { .. }) => "theme.set",
            Self::Theme(ThemeCommand::Clear) => "theme.clear",
            Self::Theme(ThemeCommand::Properties) => "theme.properties",
            Self::Status => "status",
            Self::Daemon(DaemonCommand::Run) => "daemon.run",
            Self::Daemon(DaemonCommand::Status) => "daemon.status",
        }
    }
}

fn help_target(args: &[std::ffi::OsString]) -> Option<String> {
    let mut words = Vec::new();
    let mut skip_value = false;
    for arg in args.iter().skip(1) {
        let arg = arg.to_string_lossy();
        if skip_value {
            skip_value = false;
            continue;
        }
        if arg == "--server" {
            skip_value = true;
            continue;
        }
        if arg.starts_with('-') || arg.starts_with("http://") || arg.starts_with("https://") {
            continue;
        }
        words.push(arg.into_owned());
    }

    let top = words.first()?.as_str();
    if !matches!(
        top,
        "login" | "link" | "service" | "connect" | "theme" | "status" | "daemon"
    ) {
        return None;
    }
    let child = words.get(1).map(String::as_str);
    let child_is_command = matches!(
        (top, child),
        ("link", Some("set" | "remove"))
            | ("service", Some("host" | "remove"))
            | ("theme", Some("show" | "set" | "clear" | "properties"))
            | ("daemon", Some("run" | "status"))
    );
    Some(if child_is_command {
        format!("{top}.{}", child.unwrap())
    } else {
        top.to_string()
    })
}

fn help_suggestion(command: Option<&str>) -> String {
    let path = command.map(|value| value.replace('.', " "));
    match path {
        Some(path) => format!("Run `devsite {path} --help` for valid arguments."),
        None => "Run `devsite --help` to list available commands.".to_string(),
    }
}

fn runtime_suggestions(command: &str, err: &anyhow::Error) -> Vec<String> {
    let mut suggestions = Vec::new();
    let message = format!("{err:#}");
    if message.contains("not signed in") || message.contains("run `devsite login` first") {
        suggestions.push(
            "Create a machine credential on dev.site, then run `devsite login TOKEN`.".to_string(),
        );
    }
    suggestions.push(help_suggestion(Some(command)));
    suggestions
}

#[derive(Deserialize)]
struct ThemeResponse {
    css: String,
}

#[derive(Deserialize)]
struct ThemeProperties {
    properties: Vec<ThemeProperty>,
}

#[derive(Deserialize, Serialize)]
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
    visibility: String,
    /// Set for links only; a service's target never leaves the machine serving it.
    url: Option<String>,
    folder: Option<String>,
    #[serde(default)]
    shares: Vec<ResourceShare>,
}

#[derive(Deserialize)]
struct ResourceShare {
    handle: String,
}

#[tokio::main]
async fn main() {
    let args = std::env::args_os().collect::<Vec<_>>();
    let json_requested = args.iter().any(|arg| arg == "--json");
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(err) if err.kind() == ErrorKind::DisplayHelp && json_requested => {
            Output::json().success(
                "help",
                serde_json::json!({
                    "command": help_target(&args),
                    "text": err.to_string(),
                }),
            );
            return;
        }
        Err(err) if err.kind() == ErrorKind::DisplayVersion && json_requested => {
            Output::json().success(
                "version",
                serde_json::json!({ "text": err.to_string().trim() }),
            );
            return;
        }
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            err.print().ok();
            return;
        }
        Err(err) if json_requested => {
            let command = help_target(&args);
            Output::json().error(
                "usage",
                command.as_deref(),
                &anyhow::anyhow!(err.to_string()),
                &[help_suggestion(command.as_deref())],
            );
            std::process::exit(2);
        }
        Err(err) => err.exit(),
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "devsite=info,devsite_daemon=info,warn".into()),
        )
        .with_target(false)
        .init();

    let output = Output { json: cli.json };
    let command = cli.command.name();
    if let Err(err) = run(cli, output).await {
        let suggestions = runtime_suggestions(command, &err);
        output.error("runtime", Some(command), &err, &suggestions);
        std::process::exit(1);
    }
}

#[derive(Clone, Copy)]
struct Output {
    json: bool,
}

impl Output {
    const fn json() -> Self {
        Self { json: true }
    }

    fn success(&self, command: &str, result: serde_json::Value) {
        if self.json {
            self.write(&serde_json::json!({
                "schema_version": 1,
                "ok": true,
                "command": command,
                "result": result,
            }));
        }
    }

    fn event(&self, command: &str, event: &str, data: serde_json::Value) {
        if self.json {
            self.write(&serde_json::json!({
                "schema_version": 1,
                "ok": true,
                "command": command,
                "event": event,
                "data": data,
            }));
        }
    }

    fn error(
        &self,
        kind: &str,
        command: Option<&str>,
        err: &anyhow::Error,
        suggestions: &[String],
    ) {
        if self.json {
            let causes = err
                .chain()
                .skip(1)
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            self.write(&serde_json::json!({
                "schema_version": 1,
                "ok": false,
                "command": command,
                "error": {
                    "kind": kind,
                    "message": err.to_string(),
                    "causes": causes,
                    "suggestions": suggestions,
                },
            }));
        } else {
            eprintln!("error: {err:#}");
            for suggestion in suggestions {
                eprintln!("suggestion: {suggestion}");
            }
        }
    }

    fn write(&self, value: &serde_json::Value) {
        use std::io::Write;

        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        serde_json::to_writer(&mut stdout, value).expect("JSON values serialize");
        writeln!(stdout).expect("JSON output writes");
        stdout.flush().expect("JSON output flushes");
    }
}

async fn run(cli: Cli, output: Output) -> Result<()> {
    let paths = Paths::discover()?;

    match cli.command {
        Command::Login { token } => login(&paths, &cli.server, token, output).await,
        Command::Link(LinkCommand::Set {
            name,
            url,
            public,
            share,
            folder,
        }) => {
            set_link(
                &paths,
                &cli.server,
                &name,
                &url,
                public,
                share,
                folder,
                output,
            )
            .await
        }
        Command::Link(LinkCommand::Remove { name }) => {
            remove_link(&paths, &cli.server, &name, output).await
        }
        Command::Service(ServiceCommand::Host {
            port,
            name,
            share,
            folder,
        }) => host_service(&paths, &cli.server, port, name, share, folder, output).await,
        Command::Service(ServiceCommand::Remove { name }) => {
            remove_service(&paths, &cli.server, &name, output).await
        }
        Command::Connect { ticket, listen } => connect(&cli.server, &ticket, listen, output).await,
        Command::Theme(command) => theme(&paths, &cli.server, command, output).await,
        Command::Status => status(&paths, output),
        Command::Daemon(DaemonCommand::Run) => run_daemon(&paths, &cli.server, output).await,
        Command::Daemon(DaemonCommand::Status) => daemon_status(&paths, output),
    }
}

fn load_authenticated(paths: &Paths) -> Result<DaemonConfig> {
    let config = paths.load_config()?;
    if config.machine_credential.is_none() {
        bail!("not signed in — run `devsite login` first");
    }
    Ok(config)
}

async fn login(paths: &Paths, server: &str, token: Option<String>, output: Output) -> Result<()> {
    let token = match token {
        Some(token) => token,
        None if output.json => bail!("TOKEN is required with --json"),
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
    let control_plane_key = config.control_plane_key.unwrap();
    if output.json {
        output.success(
            "login",
            serde_json::json!({
                "handle": handle,
                "server": server.trim_end_matches('/'),
                "minimum_cli_version": server_config.minimum_cli_version,
                "control_plane_key": control_plane_key,
            }),
        );
    } else {
        println!("signed in as {handle}");
        println!(
            "server requires CLI {} or newer",
            server_config.minimum_cli_version
        );
        println!("pinned control plane key {control_plane_key}");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn set_link(
    paths: &Paths,
    server: &str,
    name: &str,
    url: &str,
    public: bool,
    share: Vec<String>,
    folder: Option<String>,
    output: Output,
) -> Result<()> {
    let visibility = if public {
        Visibility::Public
    } else if share.is_empty() {
        Visibility::Private
    } else {
        Visibility::Shared
    };
    let share = normalized_handles(&share);
    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let update = warn_on_upsert(
        &api,
        "link",
        name,
        visibility,
        Some(url),
        folder.as_deref(),
        &share,
    )
    .await?;
    if !output.json {
        if let Some(update) = &update {
            update.print_human();
        }
    }
    let response: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": name,
                "kind": "link",
                "visibility": visibility_str(visibility),
                "url": url,
                "share_with": share,
                "folder": folder,
            }),
        )
        .await?;
    if output.json {
        output.success(
            "link.set",
            serde_json::json!({
                "resource_id": response.resource_id,
                "name": name,
                "url": url,
                "visibility": visibility_str(visibility),
                "folder": folder,
                "recipients": share,
                "update": update,
            }),
        );
    } else {
        println!("set link {name} → {url} ({})", visibility_str(visibility));
        if let Some(folder) = &folder {
            println!("  in {folder}");
        }
        if !share.is_empty() {
            println!("  invited {}", display_handles(&share));
        }
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

async fn remove_link(paths: &Paths, server: &str, name: &str, output: Output) -> Result<()> {
    let removed = remove_resource(paths, server, name, "link").await?;
    let url = removed.url.unwrap_or_default();
    if output.json {
        output.success(
            "link.remove",
            serde_json::json!({ "resource_id": removed.resource_id, "name": name, "url": url }),
        );
    } else {
        println!("removed link {name} → {url}");
    }
    Ok(())
}

/// Stop serving a local service and take it off the profile.
///
/// Both halves matter and in this order: the control plane forgets it, then this
/// machine does. A daemon that kept serving a resource the control plane has
/// deleted is harmless — no capability can be issued for it any more — but a
/// config that still lists it would re-register the name the next time it is hosted.
async fn remove_service(paths: &Paths, server: &str, name: &str, output: Output) -> Result<()> {
    let removed = remove_resource(paths, server, name, "service").await?;

    let mut config = paths.load_config()?;
    let before = config.resources.len();
    config.resources.retain(|r| r.name != name);
    paths.save_config(&config)?;

    let was_hosted_here = config.resources.len() != before;
    if output.json {
        output.success(
            "service.remove",
            serde_json::json!({
                "resource_id": removed.resource_id,
                "name": name,
                "was_hosted_here": was_hosted_here,
            }),
        );
    } else {
        println!("removed service {name}");
        if was_hosted_here {
            println!("  a running daemon will stop serving it automatically");
        } else {
            println!("  (this machine was not serving it; removed from your profile)");
        }
    }
    Ok(())
}

async fn host_service(
    paths: &Paths,
    server: &str,
    port: u16,
    name: Option<String>,
    share: Vec<String>,
    folder: Option<String>,
    output: Output,
) -> Result<()> {
    if port == 0 {
        bail!("port 0 cannot be hosted");
    }
    let name = name.unwrap_or_else(|| format!("port {port}"));
    let folder = Some(folder.unwrap_or_else(|| "Services".to_string()));
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let visibility = if share.is_empty() {
        Visibility::Private
    } else {
        Visibility::Shared
    };
    let share = normalized_handles(&share);

    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let update = warn_on_upsert(
        &api,
        "service",
        &name,
        visibility,
        None,
        folder.as_deref(),
        &share,
    )
    .await?;
    if !output.json {
        if let Some(update) = &update {
            update.print_human();
        }
    }

    let response: CreateResourceResponse = api
        .post(
            "/api/resources",
            &serde_json::json!({
                "name": &name,
                "kind": "service",
                "visibility": visibility_str(visibility),
                // Deliberately absent: the local target never leaves this machine.
                "share_with": share,
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
    config.resources.push(HostedService {
        resource_id,
        name: name.clone(),
        target,
        visibility,
    });
    paths.save_config(&config)?;

    let daemon_running = paths.daemon_running()?;
    if output.json {
        output.success(
            "service.host",
            serde_json::json!({
                "resource_id": resource_id.to_string(),
                "name": name,
                "target": target.to_string(),
                "visibility": visibility_str(visibility),
                "folder": folder,
                "recipients": share,
                "url": format!("{server}/s/{resource_id}"),
                "daemon": daemon_state(daemon_running),
                "update": update,
            }),
        );
    } else {
        println!("hosting {name} → {target} ({})", visibility_str(visibility));
        if let Some(folder) = &folder {
            println!("  in {folder}");
        }
        if !share.is_empty() {
            println!("  invited {}", display_handles(&share));
        }
        println!("  {server}/s/{resource_id}");
        println!();
        print_daemon_status(paths, output)?;
    }
    Ok(())
}

async fn connect(server: &str, ticket: &str, listen: SocketAddr, output: Output) -> Result<()> {
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

    if output.json {
        output.event(
            "connect",
            "listening",
            serde_json::json!({
                "name": redeemed.name,
                "resource_id": redeemed.resource_id,
                "resource_url": format!("{server}/s/{}", redeemed.resource_id),
                "listen": bound.to_string(),
                "expires_at": redeemed.expires_at,
            }),
        );
    } else {
        println!(
            "connected to {} ({server}/s/{})",
            redeemed.name, redeemed.resource_id
        );
        println!("  listening on {bound}");
        println!("  session expires at unix time {}", redeemed.expires_at);
        println!("  press Ctrl-C to stop");
    }

    loop {
        let (local, peer) = tokio::select! {
            accepted = listener.accept() => accepted.context("accepting local connection")?,
            _ = tokio::signal::ctrl_c() => {
                if output.json {
                    output.event("connect", "shutdown", serde_json::json!({}));
                } else {
                    println!("\nshutting down");
                }
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

async fn theme(paths: &Paths, server: &str, command: ThemeCommand, output: Output) -> Result<()> {
    // The property list is public: it is the documentation, and it comes from
    // the binary that enforces it rather than from a copy kept here.
    if let ThemeCommand::Properties = command {
        let api = ControlPlane::new(server, None);
        let listing: ThemeProperties = api.get("/api/theme/properties").await?;
        if output.json {
            output.success(
                "theme.properties",
                serde_json::json!({ "properties": listing.properties }),
            );
        } else {
            for property in listing.properties {
                println!("{:<44} {}", property.name, property.accepts);
            }
        }
        return Ok(());
    }

    let config = load_authenticated(paths)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());

    match command {
        ThemeCommand::Properties => unreachable!("handled above, before authentication"),
        ThemeCommand::Show => {
            let theme: ThemeResponse = api.get("/api/theme").await?;
            if output.json {
                output.success("theme.show", serde_json::json!({ "css": theme.css }));
            } else if theme.css.trim().is_empty() {
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
            if output.json {
                output.success("theme.set", serde_json::json!({ "css": saved.css }));
            } else {
                print!("{}", saved.css);
                println!("theme saved");
            }
        }
        ThemeCommand::Clear => {
            let _: ThemeResponse = api
                .put("/api/theme", &serde_json::json!({ "css": "" }))
                .await?;
            if output.json {
                output.success("theme.clear", serde_json::json!({ "css": "" }));
            } else {
                println!("theme cleared");
            }
        }
    }
    Ok(())
}

fn normalized_handles(handles: &[String]) -> Vec<String> {
    let mut unique = std::collections::BTreeMap::new();
    for handle in handles {
        let handle = handle.trim_start_matches('@');
        unique
            .entry(handle.to_ascii_lowercase())
            .or_insert_with(|| handle.to_string());
    }
    unique.into_values().collect()
}

fn display_handles(handles: &[String]) -> String {
    handles
        .iter()
        .map(|handle| format!("@{handle}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[allow(clippy::too_many_arguments)]
async fn warn_on_upsert(
    api: &ControlPlane,
    kind: &str,
    name: &str,
    visibility: Visibility,
    url: Option<&str>,
    folder: Option<&str>,
    shares: &[String],
) -> Result<Option<UpsertWarning>> {
    let listing: ResourceListing = api.get("/api/resources").await?;
    let Some(existing) = listing
        .resources
        .into_iter()
        .find(|resource| resource.kind == kind && resource.name == name)
    else {
        return Ok(None);
    };

    let desired_visibility = visibility_str(visibility);
    let mut changes = Vec::new();
    if existing.visibility != desired_visibility {
        changes.push(UpsertChange {
            field: "visibility",
            from: existing.visibility.clone(),
            to: desired_visibility.to_string(),
        });
    }

    let existing_shares = existing
        .shares
        .iter()
        .map(|share| share.handle.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let desired_shares = shares
        .iter()
        .map(|handle| handle.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    if existing_shares != desired_shares {
        let before = existing
            .shares
            .iter()
            .map(|share| share.handle.clone())
            .collect::<Vec<_>>();
        changes.push(UpsertChange {
            field: "recipients",
            from: if before.is_empty() {
                "none".to_string()
            } else {
                display_handles(&before)
            },
            to: if shares.is_empty() {
                "none".to_string()
            } else {
                display_handles(shares)
            },
        });
    }

    let mut requires_fresh_approval = false;
    if existing.url.as_deref() != url {
        changes.push(UpsertChange {
            field: "destination",
            from: existing.url.as_deref().unwrap_or("none").to_string(),
            to: url.unwrap_or("none").to_string(),
        });
        if existing.visibility == "shared" || desired_visibility == "shared" {
            requires_fresh_approval = true;
        }
    }
    if existing.folder.as_deref() != folder {
        changes.push(UpsertChange {
            field: "folder",
            from: existing.folder.as_deref().unwrap_or("none").to_string(),
            to: folder.unwrap_or("none").to_string(),
        });
    }
    Ok(Some(UpsertWarning {
        kind: kind.to_string(),
        name: name.to_string(),
        changes,
        requires_fresh_approval,
    }))
}

#[derive(Serialize)]
struct UpsertWarning {
    kind: String,
    name: String,
    changes: Vec<UpsertChange>,
    requires_fresh_approval: bool,
}

#[derive(Serialize)]
struct UpsertChange {
    field: &'static str,
    from: String,
    to: String,
}

impl UpsertWarning {
    fn print_human(&self) {
        eprintln!("warning: updating existing {} `{}`", self.kind, self.name);
        if self.changes.is_empty() {
            eprintln!("  no visibility, recipient, destination, or folder changes");
        } else {
            for change in &self.changes {
                eprintln!("  {}: {} → {}", change.field, change.from, change.to);
            }
        }
        if self.requires_fresh_approval {
            eprintln!("  recipients must approve the new destination again");
        }
    }
}

fn visibility_str(visibility: Visibility) -> &'static str {
    match visibility {
        Visibility::Public => "public",
        Visibility::Private => "private",
        Visibility::Shared => "shared",
    }
}

fn status(paths: &Paths, output: Output) -> Result<()> {
    let config = paths.load_config()?;
    let daemon_running = paths.daemon_running()?;
    if output.json {
        let services = config
            .resources
            .iter()
            .map(|resource| {
                serde_json::json!({
                    "resource_id": resource.resource_id.to_string(),
                    "name": resource.name,
                    "visibility": visibility_str(resource.visibility),
                    "target": resource.target.to_string(),
                })
            })
            .collect::<Vec<_>>();
        output.success(
            "status",
            serde_json::json!({
                "config_path": paths.config(),
                "identity_path": paths.identity(),
                "server": config.server_url,
                "control_plane_key": config.control_plane_key,
                "daemon": daemon_state(daemon_running),
                "services": services,
            }),
        );
    } else {
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
        println!(
            "daemon     {}",
            if daemon_running { "running" } else { "stopped" }
        );
        if !daemon_running {
            print_daemon_start_hint();
        }

        if config.resources.is_empty() {
            println!("\nno services hosted yet");
            return Ok(());
        }
        println!("\nhosted services:");
        for resource in &config.resources {
            println!(
                "  {:<16} {:<10} {}",
                resource.name,
                visibility_str(resource.visibility),
                resource.target
            );
        }
    }
    Ok(())
}

fn daemon_status(paths: &Paths, output: Output) -> Result<()> {
    let running = paths.daemon_running()?;
    if output.json {
        output.success("daemon.status", daemon_state(running));
        Ok(())
    } else {
        print_daemon_status(paths, output)
    }
}

fn print_daemon_status(paths: &Paths, _output: Output) -> Result<()> {
    if paths.daemon_running()? {
        println!("daemon is running; config changes reload automatically");
    } else {
        println!("daemon is stopped; this service is not reachable yet");
        print_daemon_start_hint();
    }
    Ok(())
}

fn daemon_state(running: bool) -> serde_json::Value {
    serde_json::json!({
        "running": running,
        "start_hints": if running { Vec::new() } else { daemon_start_hints().to_vec() },
    })
}

fn print_daemon_start_hint() {
    for hint in daemon_start_hints() {
        println!("  {hint}");
    }
}

#[cfg(target_os = "macos")]
fn daemon_start_hints() -> &'static [&'static str] {
    &[
        "start it with `brew services start devsite`",
        "or keep `devsite daemon run` alive with another service manager",
    ]
}

#[cfg(target_os = "linux")]
fn daemon_start_hints() -> &'static [&'static str] {
    &[
        "start it with `systemctl --user enable --now devsite.service`",
        "or keep `devsite daemon run` alive with another service manager",
    ]
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn daemon_start_hints() -> &'static [&'static str] {
    &["keep `devsite daemon run` alive with your service manager"]
}

async fn run_daemon(paths: &Paths, server: &str, output: Output) -> Result<()> {
    let config = load_authenticated(paths)?;
    let _daemon_lock = paths
        .try_daemon_lock()?
        .context("a daemon is already running for this config directory")?;
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

    if output.json {
        output.event(
            "daemon.run",
            "online",
            serde_json::json!({ "endpoint_id": endpoint_id, "relay": relay }),
        );
    } else {
        println!("daemon online");
        println!("  endpoint {endpoint_id}");
        println!("  relay    {relay}");
    }

    let reload_paths = Paths {
        root: paths.root.clone(),
    };
    tokio::select! {
        result = Arc::clone(&daemon).serve() => result?,
        result = reload_config(reload_paths, Arc::clone(&daemon), output) => result?,
        _ = tokio::signal::ctrl_c() => {
            if output.json {
                output.event("daemon.run", "shutdown", serde_json::json!({}));
            } else {
                println!("\nshutting down");
            }
        },
    }
    daemon.close().await;
    Ok(())
}

async fn reload_config(paths: Paths, daemon: Arc<Daemon>, output: Output) -> Result<()> {
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
                    if output.json {
                        output.event("daemon.run", "reloaded", serde_json::json!({}));
                    } else {
                        println!("reloaded hosted services");
                    }
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
