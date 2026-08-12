//! `devsite` — configure a profile and host local services.

mod client;

use anyhow::{bail, Context, Result};
use clap::{error::ErrorKind, Parser, Subcommand};
use devsite_client::{ClientEndpoint, ServiceStream};
use devsite_daemon::config::{DaemonConfig, HostedService, Paths, Visibility};
use devsite_daemon::Daemon;
use devsite_proto::{AccountId, ResourceId, SignedCapability};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{copy, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::client::ControlPlane;

#[derive(Parser)]
#[command(
    name = "devsite",
    version,
    about = "Share public work and reach your local services",
    after_help = "Typical workflows:\n  devsite login dmt_...\n  devsite link set --name docs --url https://example.com --public\n  devsite service host 3000 --name app\n  devsite connect dst_...\n\nUse `devsite <command> --help` for command-specific arguments."
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
    /// Store a revocable machine credential and pin the control plane's signing key.
    Login {
        /// Single-use machine enrollment ticket created on the signed-in dashboard.
        token: Option<String>,
    },
    /// Manage ordinary external links.
    #[command(subcommand)]
    Link(LinkCommand),
    /// Inspect resources stored on the control plane.
    #[command(subcommand)]
    Resources(ResourcesCommand),
    /// Host local TCP services.
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Request and grant short-lived endpoint-bound service access.
    #[command(subcommand)]
    Access(AccessCommand),
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
    /// Diagnose local configuration, control-plane compatibility, and resource drift.
    Doctor,
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
        /// Validate and show the exact change without applying it.
        #[arg(long, visible_alias = "dry-run")]
        plan: bool,
    },
    /// Take a link off your profile.
    Remove {
        /// Name previously passed to `link set`.
        name: String,
        /// Show what would be removed without applying it.
        #[arg(long, visible_alias = "dry-run")]
        plan: bool,
    },
}

#[derive(Subcommand)]
enum ResourcesCommand {
    /// List owned links and services with share and local-hosting state.
    List,
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
        /// Validate and show the exact change without applying it.
        #[arg(long, visible_alias = "dry-run")]
        plan: bool,
    },
    /// Stop hosting a service and take it off your profile.
    Remove {
        /// Name previously passed to `service host`.
        name: String,
        /// Show what would be removed without applying it.
        #[arg(long, visible_alias = "dry-run")]
        plan: bool,
    },
}

#[derive(Subcommand)]
enum AccessCommand {
    /// Create a signed request without contacting the control plane.
    Request {
        /// Human service keyword for a trusted granting party to resolve.
        service: String,
        /// Public JSON request to give to the granting party.
        #[arg(long, value_name = "FILE")]
        request: std::path::PathBuf,
        /// Private endpoint key retained by the requesting sandbox.
        #[arg(long, value_name = "FILE")]
        key: std::path::PathBuf,
        /// Seconds before the request itself expires (maximum 600).
        #[arg(long, default_value_t = 300)]
        ttl: u64,
    },
    /// Find services that this granting party may delegate.
    Resolve { keyword: String },
    /// Validate or issue a grant for a signed request.
    Grant {
        /// Signed request JSON received from the sandboxed agent.
        #[arg(long, value_name = "FILE")]
        request: std::path::PathBuf,
        /// Canonical resource id. Omit only when the keyword has one unambiguous match.
        #[arg(long)]
        resource: Option<String>,
        /// Grant lifetime in seconds (maximum 900).
        #[arg(long, default_value_t = 900)]
        ttl: u64,
        /// Validate and show the exact endpoint-bound grant without issuing it.
        #[arg(long, visible_alias = "dry-run")]
        plan: bool,
        /// Server-signed token returned by an approved plan.
        #[arg(long, requires = "request")]
        approved_plan: Option<String>,
    },
    /// Forward a local TCP port with an endpoint-bound delegated access grant.
    Connect {
        /// Session grant returned by the granting party.
        grant: String,
        /// Private endpoint key created with `access request`.
        #[arg(long, value_name = "FILE")]
        key: std::path::PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
    },
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Run the daemon in the foreground.
    Run,
    /// Report whether a daemon is serving this machine's config.
    Status,
}

/// Profile presentation is a list of `--pico-*` theme declarations and bounded
/// `--devsite-*` layout settings checked by the control plane. There is no theme
/// dropdown and no arbitrary CSS.
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
    /// List every profile presentation property and what it accepts.
    Properties,
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Login { .. } => "login",
            Self::Link(LinkCommand::Set { .. }) => "link.set",
            Self::Link(LinkCommand::Remove { .. }) => "link.remove",
            Self::Resources(ResourcesCommand::List) => "resources.list",
            Self::Service(ServiceCommand::Host { .. }) => "service.host",
            Self::Service(ServiceCommand::Remove { .. }) => "service.remove",
            Self::Access(AccessCommand::Request { .. }) => "access.request",
            Self::Access(AccessCommand::Resolve { .. }) => "access.resolve",
            Self::Access(AccessCommand::Grant { plan: true, .. }) => "access.grant.plan",
            Self::Access(AccessCommand::Grant { plan: false, .. }) => "access.grant",
            Self::Access(AccessCommand::Connect { .. }) => "access.connect",
            Self::Connect { .. } => "connect",
            Self::Theme(ThemeCommand::Show) => "theme.show",
            Self::Theme(ThemeCommand::Set { .. }) => "theme.set",
            Self::Theme(ThemeCommand::Clear) => "theme.clear",
            Self::Theme(ThemeCommand::Properties) => "theme.properties",
            Self::Status => "status",
            Self::Doctor => "doctor",
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
        "login"
            | "link"
            | "resources"
            | "service"
            | "access"
            | "connect"
            | "theme"
            | "status"
            | "doctor"
            | "daemon"
    ) {
        return None;
    }
    let child = words.get(1).map(String::as_str);
    let child_is_command = matches!(
        (top, child),
        ("link", Some("set" | "remove"))
            | ("resources", Some("list"))
            | ("service", Some("host" | "remove"))
            | ("access", Some("request" | "resolve" | "grant" | "connect"))
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
            "Create a machine ticket on dev.site, then run `devsite login TICKET`.".to_string(),
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
    server_version: String,
    daemon_protocol: String,
}

#[derive(Deserialize)]
struct CreateResourceResponse {
    resource_id: String,
    #[serde(default)]
    plan: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ResourcePlanResponse {
    plan: serde_json::Value,
}

#[derive(Deserialize)]
struct MeResponse {
    handle: Option<String>,
}

#[derive(Deserialize)]
struct DaemonInfo {
    credential_endpoint_id: String,
    registered_endpoint_id: Option<String>,
    registration_matches_credential: bool,
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
struct EnrollMachineResponse {
    machine_credential: String,
    endpoint_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ServiceGrantRequest {
    schema_version: u32,
    request_id: String,
    service: String,
    requester_endpoint_id: String,
    expires_at: u64,
    proof: String,
}

#[derive(Deserialize, Serialize)]
struct AccessibleService {
    resource_id: String,
    name: String,
    owner_handle: Option<String>,
    visibility: String,
    exact_name_match: bool,
}

#[derive(Deserialize)]
struct AccessibleServicesResponse {
    keyword: String,
    services: Vec<AccessibleService>,
}

#[derive(Deserialize, Serialize)]
struct ServiceGrantResponse {
    grant: String,
    request_id: String,
    resource_id: String,
    name: String,
    owner_id: String,
    owner_handle: Option<String>,
    requester_endpoint_id: String,
    expires_at: u64,
}

#[derive(Deserialize)]
struct TunnelSessionInfo {
    resource_id: String,
    name: String,
    requester_endpoint_id: String,
    expires_at: u64,
    brokered: bool,
}

#[derive(Deserialize)]
struct AuthorizationListing {
    authorizations: Vec<ServiceAuthorization>,
}

#[derive(Deserialize)]
struct ServiceAuthorization {
    viewer_id: String,
    resource_id: String,
}

#[derive(Deserialize)]
struct ResourceListing {
    resources: Vec<Resource>,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
struct ResourceShare {
    handle: String,
    status: String,
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
            plan,
        }) => set_link(&paths, &name, &url, public, share, folder, plan, output).await,
        Command::Link(LinkCommand::Remove { name, plan }) => {
            remove_link(&paths, &name, plan, output).await
        }
        Command::Resources(ResourcesCommand::List) => resources_list(&paths, output).await,
        Command::Service(ServiceCommand::Host {
            port,
            name,
            share,
            folder,
            plan,
        }) => host_service(&paths, port, name, share, folder, plan, output).await,
        Command::Service(ServiceCommand::Remove { name, plan }) => {
            remove_service(&paths, &name, plan, output).await
        }
        Command::Access(AccessCommand::Request {
            service,
            request,
            key,
            ttl,
        }) => create_access_request(&service, &request, &key, ttl, output),
        Command::Access(AccessCommand::Resolve { keyword }) => {
            resolve_access(&paths, &keyword, output).await
        }
        Command::Access(AccessCommand::Grant {
            request,
            resource,
            ttl,
            plan,
            approved_plan,
        }) => {
            grant_access(
                &paths,
                &request,
                resource.as_deref(),
                ttl,
                plan,
                approved_plan.as_deref(),
                output,
            )
            .await
        }
        Command::Access(AccessCommand::Connect { grant, key, listen }) => {
            connect_grant(&cli.server, &grant, &key, listen, output).await
        }
        Command::Connect { ticket, listen } => connect(&cli.server, &ticket, listen, output).await,
        Command::Theme(command) => theme(&paths, &cli.server, command, output).await,
        Command::Status => status(&paths, output),
        Command::Doctor => doctor(&paths, output).await,
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

fn enrolled_server(config: &DaemonConfig) -> Result<&str> {
    config
        .server_url
        .as_deref()
        .context("this credential is not bound to a control-plane origin — log in again")
}

fn validate_cli_version(minimum: &str, current: &str) -> Result<()> {
    let minimum = semver::Version::parse(minimum)
        .context("server reported an invalid minimum CLI version")?;
    let current =
        semver::Version::parse(current).context("this CLI has invalid version metadata")?;
    if current < minimum {
        bail!("server requires CLI {minimum} or newer, but this is CLI {current}");
    }
    Ok(())
}

fn green_check() -> &'static str {
    if std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() {
        "\x1b[32m✓\x1b[0m"
    } else {
        "✓"
    }
}

async fn login(paths: &Paths, server: &str, token: Option<String>, output: Output) -> Result<()> {
    let ticket = match token {
        Some(ticket) => ticket,
        None if output.json => bail!("TOKEN is required with --json"),
        None => {
            println!("Open {server}, create a machine ticket, and paste it here.");
            print!("ticket: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };
    if ticket.is_empty() {
        bail!("no ticket provided");
    }

    let bootstrap = ControlPlane::new(server, None);
    let server_config: PublicConfig = bootstrap.get("/api/config").await?;
    if server_config.api_version != 3 {
        bail!(
            "this CLI speaks API version 3, but the server reports version {}",
            server_config.api_version
        );
    }
    let cli_version = env!("CARGO_PKG_VERSION");
    validate_cli_version(&server_config.minimum_cli_version, cli_version)?;
    let pubkey: PubKeyResponse = bootstrap.get("/api/pubkey").await?;
    let identity = paths.load_or_create_identity()?;
    let endpoint_id = identity.public().to_string();
    let enrollment = ControlPlane::new(server, Some(ticket));
    let enrolled: EnrollMachineResponse = enrollment
        .put(
            "/api/machine/enroll",
            &serde_json::json!({
                "endpoint_id": endpoint_id,
                "proof": endpoint_proof(&identity),
            }),
        )
        .await
        .context("enrolling this machine ticket")?;
    if enrolled.endpoint_id != endpoint_id {
        bail!("the server enrolled a different endpoint identity");
    }

    // Confirm the rotated credential works before storing it.
    let api = ControlPlane::new(server, Some(enrolled.machine_credential.clone()));
    let me: serde_json::Value = api
        .get("/api/me")
        .await
        .context("the enrolled machine credential was not accepted")?;

    let mut config = paths.load_config()?;
    config.server_url = Some(server.trim_end_matches('/').to_string());
    config.machine_credential = Some(enrolled.machine_credential);
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
                "cli_version": cli_version,
                "minimum_cli_version": server_config.minimum_cli_version,
                "cli_compatible": true,
                "control_plane_key": control_plane_key,
            }),
        );
    } else {
        println!("signed in as {handle}");
        println!(
            "{} CLI {} meets server requirement ({} or newer)",
            green_check(),
            cli_version,
            server_config.minimum_cli_version,
        );
        println!("pinned control plane key {control_plane_key}");
    }
    Ok(())
}

fn endpoint_proof(secret: &iroh::SecretKey) -> String {
    let endpoint = *secret.public().as_bytes();
    let signature = secret.sign(&devsite_proto::machine_endpoint_proof_message(&endpoint));
    data_encoding::BASE64URL_NOPAD.encode(&signature.to_bytes())
}

#[allow(clippy::too_many_arguments)]
async fn set_link(
    paths: &Paths,
    name: &str,
    url: &str,
    public: bool,
    share: Vec<String>,
    folder: Option<String>,
    plan: bool,
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
    let server = enrolled_server(&config)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let payload = serde_json::json!({
        "name": name,
        "kind": "link",
        "visibility": visibility_str(visibility),
        "url": url,
        "share_with": share,
        "folder": folder,
    });
    if plan {
        let planned: ResourcePlanResponse = api.post("/api/resources/plan", &payload).await?;
        if output.json {
            output.success(
                "link.set",
                serde_json::json!({ "applied": false, "plan": planned.plan }),
            );
        } else {
            print_resource_plan(&planned.plan);
        }
        return Ok(());
    }
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
    let response: CreateResourceResponse = api.post("/api/resources", &payload).await?;
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
                "applied": true,
                "plan": response.plan,
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
async fn remove_resource(
    paths: &Paths,
    name: &str,
    kind: &str,
    apply: bool,
) -> Result<Option<Resource>> {
    let config = load_authenticated(paths)?;
    let server = enrolled_server(&config)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());

    let listing: ResourceListing = api.get("/api/resources").await?;
    let found = listing
        .resources
        .into_iter()
        .find(|r| r.name == name && r.kind == kind);

    if apply {
        if let Some(resource) = &found {
            api.delete(&format!("/api/resources/{}", resource.resource_id))
                .await?;
        }
    }
    Ok(found)
}

async fn remove_link(paths: &Paths, name: &str, plan: bool, output: Output) -> Result<()> {
    let removed = remove_resource(paths, name, "link", !plan)
        .await?
        .with_context(|| format!("you have no link called `{name}`"))?;
    let removal_plan = resource_removal_plan(&removed, None);
    if plan {
        if output.json {
            output.success(
                "link.remove",
                serde_json::json!({ "applied": false, "plan": removal_plan }),
            );
        } else {
            print_resource_plan(&removal_plan);
        }
        return Ok(());
    }
    let url = removed.url.unwrap_or_default();
    if output.json {
        output.success(
            "link.remove",
            serde_json::json!({
                "resource_id": removed.resource_id,
                "name": name,
                "url": url,
                "applied": true,
                "plan": removal_plan,
            }),
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
async fn remove_service(paths: &Paths, name: &str, plan: bool, output: Output) -> Result<()> {
    let mut config = paths.load_config()?;
    let local = config
        .resources
        .iter()
        .find(|resource| resource.name == name);
    let removed = remove_resource(paths, name, "service", !plan).await?;
    if removed.is_none() && local.is_none() {
        bail!("you have no service called `{name}`");
    }
    let removal_plan = match &removed {
        Some(resource) => resource_removal_plan(resource, local.map(|service| service.target)),
        None => serde_json::json!({
            "operation": "delete",
            "target": { "resource_id": null, "kind": "service", "name": name },
            "changes": [],
            "recipient_changes": [],
            "effects": [{ "code": "local_service_mapping_removed", "handles": [] }],
            "local_only": true,
        }),
    };
    if plan {
        if output.json {
            output.success(
                "service.remove",
                serde_json::json!({ "applied": false, "plan": removal_plan }),
            );
        } else {
            print_resource_plan(&removal_plan);
        }
        return Ok(());
    }

    let before = config.resources.len();
    config.resources.retain(|r| r.name != name);
    paths.save_config(&config)?;

    let was_hosted_here = config.resources.len() != before;
    let remote_already_absent = removed.is_none();
    if output.json {
        output.success(
            "service.remove",
            serde_json::json!({
                "resource_id": removed.as_ref().map(|resource| resource.resource_id.as_str()),
                "name": name,
                "was_hosted_here": was_hosted_here,
                "remote_already_absent": remote_already_absent,
                "applied": true,
                "plan": removal_plan,
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
    port: u16,
    name: Option<String>,
    share: Vec<String>,
    folder: Option<String>,
    plan: bool,
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
    let server = enrolled_server(&config)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    let payload = serde_json::json!({
        "name": &name,
        "kind": "service",
        "visibility": visibility_str(visibility),
        // Deliberately absent: the local target never leaves this machine.
        "share_with": share,
        "folder": folder,
    });
    if plan {
        let planned: ResourcePlanResponse = api.post("/api/resources/plan", &payload).await?;
        let planned = plan_with_local_changes(
            planned.plan,
            serde_json::json!([{
                "operation": "upsert_hosted_service",
                "target": target.to_string(),
            }]),
        );
        if output.json {
            output.success(
                "service.host",
                serde_json::json!({ "applied": false, "plan": planned }),
            );
        } else {
            print_resource_plan(&planned);
        }
        return Ok(());
    }
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

    let response: CreateResourceResponse = api.post("/api/resources", &payload).await?;
    let applied_plan = response.plan.map(|plan| {
        plan_with_local_changes(
            plan,
            serde_json::json!([{
                "operation": "upsert_hosted_service",
                "target": target.to_string(),
            }]),
        )
    });

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
                "applied": true,
                "plan": applied_plan,
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
    let client = Arc::new(ClientEndpoint::create().await?);
    let bootstrap = ControlPlane::new(server, None);
    let redeemed: RedeemTicketResponse = bootstrap
        .post(
            "/api/tickets/redeem",
            &serde_json::json!({
                "ticket": ticket,
                "client_endpoint_id": client.endpoint_id().to_string(),
            }),
        )
        .await
        .context("redeeming connection ticket")?;
    let api = Arc::new(ControlPlane::new(server, Some(redeemed.session_token)));
    run_tunnel(
        "connect",
        server,
        client,
        api,
        &redeemed.name,
        &redeemed.resource_id,
        redeemed.expires_at,
        listen,
        output,
    )
    .await
}

fn create_access_request(
    service: &str,
    request_path: &std::path::Path,
    key_path: &std::path::Path,
    ttl: u64,
    output: Output,
) -> Result<()> {
    let service = service.trim();
    if service.is_empty() || service.chars().count() > 80 {
        bail!("service keyword must be 1 to 80 characters");
    }
    if ttl == 0 || ttl > 10 * 60 {
        bail!("request TTL must be between 1 and 600 seconds");
    }
    if request_path == key_path {
        bail!("--request and --key must name different files");
    }

    let secret = iroh::SecretKey::generate();
    let endpoint = secret.public();
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|err| anyhow::anyhow!("generating service grant request id: {err}"))?;
    let request_id = format!("agr_{}", data_encoding::BASE64URL_NOPAD.encode(&nonce));
    let expires_at = unix_now()?.saturating_add(ttl);
    let message = devsite_proto::service_grant_request_message(
        &request_id,
        service,
        endpoint.as_bytes(),
        expires_at,
    );
    let proof = data_encoding::BASE64URL_NOPAD.encode(&secret.sign(&message).to_bytes());
    let request = ServiceGrantRequest {
        schema_version: 1,
        request_id,
        service: service.to_string(),
        requester_endpoint_id: endpoint.to_string(),
        expires_at,
        proof,
    };

    write_new_private(key_path, &secret.to_bytes())?;
    let request_json = serde_json::to_vec_pretty(&request)?;
    if let Err(err) = write_new_private(request_path, &request_json) {
        std::fs::remove_file(key_path).ok();
        return Err(err);
    }

    if output.json {
        output.success(
            "access.request",
            serde_json::json!({
                "request": request,
                "request_path": request_path,
                "key_path": key_path,
                "handoff": "share_request_only",
            }),
        );
    } else {
        println!("created signed request for {service}");
        println!(
            "  request  {} (give to the granting party)",
            request_path.display()
        );
        println!(
            "  key      {} (keep inside the requester)",
            key_path.display()
        );
        println!("  endpoint {endpoint}");
        println!("  expires  {expires_at}");
    }
    Ok(())
}

async fn resolve_access(paths: &Paths, keyword: &str, output: Output) -> Result<()> {
    let listing = resolve_access_listing(paths, keyword).await?;
    if output.json {
        output.success("access.resolve", serde_json::to_value(&listing.services)?);
    } else if listing.services.is_empty() {
        println!("no accessible services match {:?}", listing.keyword);
    } else {
        for service in listing.services {
            let owner = service
                .owner_handle
                .map(|handle| format!(" from @{handle}"))
                .unwrap_or_default();
            println!("{}  {}{}", service.resource_id, service.name, owner);
        }
    }
    Ok(())
}

async fn resolve_access_listing(
    paths: &Paths,
    keyword: &str,
) -> Result<AccessibleServicesResponse> {
    let config = load_authenticated(paths)?;
    let server = enrolled_server(&config)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    api.get_query("/api/access/services", &[("keyword", keyword)])
        .await
        .context("resolving accessible services")
}

async fn grant_access(
    paths: &Paths,
    request_path: &std::path::Path,
    resource: Option<&str>,
    ttl: u64,
    plan: bool,
    approved_plan: Option<&str>,
    output: Output,
) -> Result<()> {
    if ttl == 0 || ttl > 15 * 60 {
        bail!("grant TTL must be between 1 and 900 seconds");
    }
    if plan && approved_plan.is_some() {
        bail!("--approved-plan cannot be combined with --plan");
    }
    if !plan && approved_plan.is_none() {
        bail!("apply requires --approved-plan from the exact reviewed plan");
    }
    let approved_claims = approved_plan
        .map(|token| {
            devsite_proto::access_plan::SignedServiceGrantPlan::from_token(token)
                .and_then(|plan| plan.unverified_claims())
                .map_err(|_| anyhow::anyhow!("--approved-plan is malformed"))
        })
        .transpose()?;
    let request: ServiceGrantRequest = serde_json::from_slice(
        &std::fs::read(request_path)
            .with_context(|| format!("reading {}", request_path.display()))?,
    )
    .with_context(|| format!("parsing {}", request_path.display()))?;
    if approved_claims.as_ref().is_some_and(|claims| {
        claims.schema_version != request.schema_version
            || claims.request_id != request.request_id
            || claims.service != request.service
            || claims.requester_endpoint_id != request.requester_endpoint_id
            || claims.request_expires_at != request.expires_at
    }) {
        bail!("--approved-plan does not match the signed request file");
    }
    let listing = resolve_access_listing(paths, &request.service).await?;
    let resource_id = match (resource, &approved_claims) {
        (Some(resource), Some(claims)) if resource != claims.resource_id => {
            bail!("--resource does not match --approved-plan")
        }
        (_, Some(claims)) => {
            if !listing
                .services
                .iter()
                .any(|item| item.resource_id == claims.resource_id)
            {
                bail!("the approved service is no longer accessible to this granting party");
            }
            claims.resource_id.clone()
        }
        (Some(resource), None) => {
            if !listing
                .services
                .iter()
                .any(|item| item.resource_id == resource)
            {
                bail!(
                    "resource {resource} is not among the services matching {:?}",
                    request.service
                );
            }
            resource.to_string()
        }
        (None, None) => select_access_service(&request.service, &listing.services)?
            .resource_id
            .clone(),
    };
    let expires_at = match &approved_claims {
        Some(claims) => claims.grant_expires_at,
        None => unix_now()?.saturating_add(ttl),
    };
    let requester: iroh::EndpointId = request
        .requester_endpoint_id
        .parse()
        .context("request contains an invalid endpoint id")?;
    let broker = paths.load_or_create_identity()?;
    let message = devsite_proto::service_grant_issue_message(
        &request.request_id,
        &resource_id,
        requester.as_bytes(),
        expires_at,
    );
    let broker_proof = data_encoding::BASE64URL_NOPAD.encode(&broker.sign(&message).to_bytes());
    let body = serde_json::json!({
        "request": request,
        "resource_id": resource_id,
        "expires_at": expires_at,
        "broker_proof": broker_proof,
        "approved_plan": approved_plan,
    });
    let config = load_authenticated(paths)?;
    let server = enrolled_server(&config)?;
    let api = ControlPlane::new(server, config.machine_credential.clone());
    if plan {
        let result: serde_json::Value = api
            .post("/api/access/grants/plan", &body)
            .await
            .context("planning endpoint-bound service grant")?;
        if output.json {
            output.success("access.grant.plan", result);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        let grant: ServiceGrantResponse = api
            .post("/api/access/grants", &body)
            .await
            .context("issuing endpoint-bound service grant")?;
        if output.json {
            let mut result = serde_json::to_value(&grant)?;
            if let serde_json::Value::Object(fields) = &mut result {
                fields.insert("server".to_string(), serde_json::json!(server));
            }
            output.success("access.grant", result);
        } else {
            println!("issued {} access to {}", grant.request_id, grant.name);
            if let Some(owner) = &grant.owner_handle {
                println!("  owner    @{owner}");
            } else {
                println!("  owner    {}", grant.owner_id);
            }
            println!("  endpoint {}", grant.requester_endpoint_id);
            println!("  expires  {}", grant.expires_at);
            println!("  grant    {}", grant.grant);
        }
    }
    Ok(())
}

fn select_access_service<'a>(
    keyword: &str,
    services: &'a [AccessibleService],
) -> Result<&'a AccessibleService> {
    let exact = services
        .iter()
        .filter(|service| service.exact_name_match)
        .collect::<Vec<_>>();
    match (exact.as_slice(), services) {
        ([service], _) => Ok(*service),
        ([], [service]) => Ok(service),
        ([], []) => bail!("no accessible service matches {keyword:?}"),
        _ => bail!(
            "service keyword {keyword:?} is ambiguous; run `devsite access resolve {keyword}` and pass --resource"
        ),
    }
}

async fn connect_grant(
    server: &str,
    grant: &str,
    key_path: &std::path::Path,
    listen: SocketAddr,
    output: Output,
) -> Result<()> {
    if !grant.starts_with("dss_") {
        bail!("delegated access grant must start with dss_");
    }
    let raw = std::fs::read(key_path).with_context(|| format!("reading {}", key_path.display()))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not a 32 byte endpoint key", key_path.display()))?;
    let client =
        Arc::new(ClientEndpoint::create_with_secret(iroh::SecretKey::from_bytes(&bytes)).await?);
    let api = Arc::new(ControlPlane::new(server, Some(grant.to_string())));
    let session: TunnelSessionInfo = api
        .get("/api/tunnel/session")
        .await
        .context("validating delegated access grant")?;
    if session.requester_endpoint_id != client.endpoint_id().to_string() || !session.brokered {
        bail!("the grant is not bound to the supplied requester endpoint key");
    }
    run_tunnel(
        "access.connect",
        server,
        client,
        api,
        &session.name,
        &session.resource_id,
        session.expires_at,
        listen,
        output,
    )
    .await
}

fn unix_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

fn write_new_private(path: &std::path::Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {} without overwriting it", path.display()))?;
    use std::io::Write;
    file.write_all(contents)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel(
    command: &str,
    server: &str,
    client: Arc<ClientEndpoint>,
    api: Arc<ControlPlane>,
    name: &str,
    resource_id: &str,
    expires_at: u64,
    listen: SocketAddr,
    output: Output,
) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("--listen must be a loopback address; refusing to publish the tunnel on the LAN");
    }
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding local listener {listen}"))?;
    let bound = listener.local_addr()?;

    if output.json {
        output.event(
            command,
            "listening",
            serde_json::json!({
                "name": name,
                "resource_id": resource_id,
                "resource_url": format!("{server}/s/{resource_id}"),
                "listen": bound.to_string(),
                "expires_at": expires_at,
            }),
        );
    } else {
        println!("connected to {} ({server}/s/{})", name, resource_id);
        println!("  listening on {bound}");
        if expires_at > 0 {
            println!("  session expires at unix time {expires_at}");
        }
        println!("  press Ctrl-C to stop");
    }

    loop {
        let (local, peer) = tokio::select! {
            accepted = listener.accept() => accepted.context("accepting local connection")?,
            _ = tokio::signal::ctrl_c() => {
                if output.json {
                    output.event(command, "shutdown", serde_json::json!({}));
                } else {
                    println!("\nshutting down");
                }
                if let Err(err) = api.delete("/api/tunnel/session").await {
                    tracing::warn!("could not revoke tunnel session during shutdown: {err:#}");
                }
                client.close().await;
                return Ok(());
            }
        };
        let api = Arc::clone(&api);
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            if let Err(err) = forward_connection(&api, &client, local).await {
                tracing::warn!(%peer, "service connection failed: {err:#}");
            }
        });
    }
}

async fn forward_connection(
    api: &ControlPlane,
    client: &ClientEndpoint,
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
    let ServiceStream { mut send, mut recv } = client.connect(daemon, capability).await?;
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
    let server = enrolled_server(&config)?;
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

fn plan_with_local_changes(
    mut plan: serde_json::Value,
    local_changes: serde_json::Value,
) -> serde_json::Value {
    if let Some(object) = plan.as_object_mut() {
        object.insert("local_changes".to_string(), local_changes);
    }
    plan
}

fn resource_removal_plan(
    resource: &Resource,
    local_target: Option<SocketAddr>,
) -> serde_json::Value {
    let recipient_changes = resource
        .shares
        .iter()
        .map(|recipient| {
            serde_json::json!({
                "handle": recipient.handle,
                "from": recipient.status,
                "to": null,
                "reason": "resource_removed",
            })
        })
        .collect::<Vec<_>>();
    let accepted = resource
        .shares
        .iter()
        .filter(|recipient| recipient.status == "accepted")
        .map(|recipient| recipient.handle.clone())
        .collect::<Vec<_>>();
    let pending = resource
        .shares
        .iter()
        .filter(|recipient| recipient.status == "pending")
        .map(|recipient| recipient.handle.clone())
        .collect::<Vec<_>>();
    let mut effects = vec![serde_json::json!({
        "code": "profile_entry_removed",
        "handles": [],
    })];
    if !accepted.is_empty() {
        effects.push(serde_json::json!({
            "code": "accepted_access_revoked",
            "handles": accepted,
        }));
    }
    if !pending.is_empty() {
        effects.push(serde_json::json!({
            "code": "pending_invitations_withdrawn",
            "handles": pending,
        }));
    }
    if local_target.is_some() {
        effects.push(serde_json::json!({
            "code": "local_service_mapping_removed",
            "handles": [],
        }));
    }
    serde_json::json!({
        "operation": "delete",
        "target": {
            "resource_id": resource.resource_id,
            "kind": resource.kind,
            "name": resource.name,
        },
        "changes": [],
        "recipient_changes": recipient_changes,
        "effects": effects,
        "local_changes": local_target.map(|target| vec![serde_json::json!({
            "operation": "remove_hosted_service",
            "target": target.to_string(),
        })]).unwrap_or_default(),
    })
}

fn print_resource_plan(plan: &serde_json::Value) {
    let operation = plan["operation"].as_str().unwrap_or("change");
    let kind = plan["target"]["kind"].as_str().unwrap_or("resource");
    let name = plan["target"]["name"].as_str().unwrap_or("(unknown)");
    println!("plan: {operation} {kind} `{name}`");
    if let Some(changes) = plan["changes"].as_array() {
        for change in changes {
            println!(
                "  {}: {} → {}",
                change["field"].as_str().unwrap_or("field"),
                change["from"],
                change["to"]
            );
        }
    }
    if let Some(effects) = plan["effects"].as_array() {
        for effect in effects {
            println!("  effect: {}", effect["code"].as_str().unwrap_or("change"));
        }
    }
    println!("no changes applied");
}

async fn resources_list(paths: &Paths, output: Output) -> Result<()> {
    let config = load_authenticated(paths)?;
    let server = enrolled_server(&config)?.to_string();
    let api = ControlPlane::new(&server, config.machine_credential.clone());
    let listing: ResourceListing = api.get("/api/resources").await?;
    let daemon_running = paths.daemon_running()?;
    let remote_ids = listing
        .resources
        .iter()
        .map(|resource| resource.resource_id.clone())
        .collect::<HashSet<_>>();
    let resources = listing
        .resources
        .iter()
        .map(|resource| {
            let local = config
                .resources
                .iter()
                .find(|hosted| hosted.resource_id.to_string() == resource.resource_id);
            let mut issues = Vec::new();
            if let Some(hosted) = local {
                if visibility_str(hosted.visibility) != resource.visibility {
                    issues.push(serde_json::json!({
                        "code": "visibility_mismatch",
                        "local": visibility_str(hosted.visibility),
                        "remote": resource.visibility,
                    }));
                }
                if resource.kind != "service" {
                    issues.push(serde_json::json!({ "code": "remote_kind_mismatch" }));
                }
            }
            let state = match (resource.kind.as_str(), local, daemon_running) {
                ("link", _, _) => "profile_entry",
                ("service", Some(_), true) => "serving_here",
                ("service", Some(_), false) => "configured_here",
                ("service", None, _) => "not_configured_here",
                _ => "profile_entry",
            };
            serde_json::json!({
                "resource_id": resource.resource_id,
                "name": resource.name,
                "kind": resource.kind,
                "visibility": resource.visibility,
                "url": resource.url,
                "folder": resource.folder,
                "recipients": resource.shares,
                "local": local.map(|hosted| serde_json::json!({
                    "configured": true,
                    "target": hosted.target.to_string(),
                })),
                "state": state,
                "issues": issues,
            })
        })
        .collect::<Vec<_>>();
    let local_only_services = config
        .resources
        .iter()
        .filter(|hosted| !remote_ids.contains(&hosted.resource_id.to_string()))
        .map(|hosted| {
            serde_json::json!({
                "resource_id": hosted.resource_id.to_string(),
                "name": hosted.name,
                "kind": "service",
                "visibility": visibility_str(hosted.visibility),
                "target": hosted.target.to_string(),
                "state": "local_only",
                "issues": [{ "code": "missing_remote_resource" }],
            })
        })
        .collect::<Vec<_>>();

    if output.json {
        output.success(
            "resources.list",
            serde_json::json!({
                "server": server,
                "daemon": daemon_state(daemon_running),
                "resources": resources,
                "local_only_services": local_only_services,
            }),
        );
    } else {
        if resources.is_empty() {
            println!("no remote resources");
        }
        for resource in &resources {
            println!(
                "{:<8} {:<18} {:<18} {}",
                resource["kind"].as_str().unwrap_or("resource"),
                resource["name"].as_str().unwrap_or(""),
                resource["visibility"].as_str().unwrap_or(""),
                resource["state"].as_str().unwrap_or("")
            );
        }
        for resource in &local_only_services {
            println!(
                "service  {:<18} {:<18} local_only",
                resource["name"].as_str().unwrap_or(""),
                resource["visibility"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
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

fn push_doctor_check(
    checks: &mut Vec<serde_json::Value>,
    counts: &mut [u64; 4],
    id: &str,
    status: &str,
    message: impl Into<String>,
) {
    let index = match status {
        "pass" => 0,
        "warning" => 1,
        "failure" => 2,
        _ => 3,
    };
    counts[index] += 1;
    checks.push(serde_json::json!({
        "id": id,
        "status": status,
        "message": message.into(),
    }));
}

#[cfg(unix)]
fn private_file_permissions(path: &std::path::Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    Ok(std::fs::metadata(path)?.mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn private_file_permissions(_path: &std::path::Path) -> Result<bool> {
    Ok(true)
}

async fn doctor(paths: &Paths, output: Output) -> Result<()> {
    let mut checks = Vec::new();
    let mut actions = Vec::new();
    let mut counts = [0_u64; 4];

    let config_exists = paths.config().exists();
    let config = match paths.load_config() {
        Ok(config) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "config.readable",
                if config_exists { "pass" } else { "skipped" },
                if config_exists {
                    format!("Loaded {}.", paths.config().display())
                } else {
                    "No config file exists yet.".to_string()
                },
            );
            config
        }
        Err(err) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "config.readable",
                "failure",
                format!("{err:#}"),
            );
            DaemonConfig::default()
        }
    };
    if paths.config().exists() {
        match private_file_permissions(&paths.config()) {
            Ok(true) => push_doctor_check(
                &mut checks,
                &mut counts,
                "config.permissions",
                "pass",
                "The credential-bearing config is private.",
            ),
            Ok(false) => push_doctor_check(
                &mut checks,
                &mut counts,
                "config.permissions",
                "failure",
                "The credential-bearing config is readable by another user.",
            ),
            Err(err) => push_doctor_check(
                &mut checks,
                &mut counts,
                "config.permissions",
                "failure",
                format!("{err:#}"),
            ),
        }
    } else {
        push_doctor_check(
            &mut checks,
            &mut counts,
            "config.permissions",
            "skipped",
            "No config file exists yet.",
        );
    }

    let identity = match std::fs::read(paths.identity()) {
        Ok(raw) => {
            let parsed = raw
                .as_slice()
                .try_into()
                .map(iroh::SecretKey::from_bytes)
                .map_err(|_| anyhow::anyhow!("endpoint key is not 32 bytes"));
            match parsed {
                Ok(key) => {
                    push_doctor_check(
                        &mut checks,
                        &mut counts,
                        "identity.private_key",
                        "pass",
                        "The endpoint key is readable and valid.",
                    );
                    Some(key)
                }
                Err(err) => {
                    push_doctor_check(
                        &mut checks,
                        &mut counts,
                        "identity.private_key",
                        "failure",
                        err.to_string(),
                    );
                    None
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let legacy = paths.root.join("identity.key");
            let message = if legacy.exists() {
                "Legacy identity.key and identity.pub support ends in version 0.6.0. Run `devsite login` or `devsite daemon run` before you upgrade. The command moves these files."
            } else {
                "No endpoint identity exists yet."
            };
            push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.private_key",
                if config.machine_credential.is_some() {
                    "failure"
                } else {
                    "skipped"
                },
                message,
            );
            None
        }
        Err(err) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.private_key",
                "failure",
                format!("{err:#}"),
            );
            None
        }
    };
    if paths.identity().exists() {
        match private_file_permissions(&paths.identity()) {
            Ok(true) => push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.permissions",
                "pass",
                "The endpoint key is private.",
            ),
            Ok(false) => push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.permissions",
                "failure",
                "The endpoint key is readable by another user.",
            ),
            Err(err) => push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.permissions",
                "failure",
                format!("{err:#}"),
            ),
        }
    }

    let endpoint_id = identity.as_ref().map(|key| key.public().to_string());
    match (&endpoint_id, std::fs::read_to_string(paths.identity_public())) {
        (Some(expected), Ok(actual)) if actual.trim() == expected => push_doctor_check(
            &mut checks,
            &mut counts,
            "identity.public_key",
            "pass",
            "devsite-endpoint.pub matches the endpoint key.",
        ),
        (Some(_), Ok(_)) => push_doctor_check(
            &mut checks,
            &mut counts,
            "identity.public_key",
            "warning",
            "devsite-endpoint.pub does not match the endpoint key; login or daemon startup will rewrite it.",
        ),
        (Some(_), Err(_)) => push_doctor_check(
            &mut checks,
            &mut counts,
            "identity.public_key",
            "warning",
            "devsite-endpoint.pub is missing; login or daemon startup will create it.",
        ),
        (None, _) => push_doctor_check(
            &mut checks,
            &mut counts,
            "identity.public_key",
            "skipped",
            "No valid endpoint key is available for comparison.",
        ),
    }

    let daemon_running = paths.daemon_running()?;
    let daemon_status = if daemon_running || config.resources.is_empty() {
        "pass"
    } else {
        "warning"
    };
    push_doctor_check(
        &mut checks,
        &mut counts,
        "daemon.local",
        daemon_status,
        if daemon_running {
            "The local daemon is running.".to_string()
        } else if config.resources.is_empty() {
            "The local daemon is stopped and no services are configured.".to_string()
        } else {
            format!(
                "The local daemon is stopped while {} service(s) are configured.",
                config.resources.len()
            )
        },
    );
    if !daemon_running && !config.resources.is_empty() {
        actions.push(serde_json::json!({
            "id": "start-daemon",
            "priority": 1,
            "reason": "configured_services_not_served",
            "commands": daemon_start_commands(),
            "mutates": "local_process",
            "requires_user_input": false,
        }));
    }

    let Some(server) = config.server_url.as_deref() else {
        push_doctor_check(
            &mut checks,
            &mut counts,
            "server.reachable",
            "skipped",
            "No control plane is configured.",
        );
        actions.push(serde_json::json!({
            "id": "login",
            "priority": 1,
            "reason": "not_enrolled",
            "commands": [["devsite", "login", "TICKET"]],
            "mutates": "local_and_remote_identity",
            "requires_user_input": true,
        }));
        return write_doctor_report(output, checks, counts, actions);
    };
    let public = ControlPlane::new(server, None);
    let public_config: PublicConfig = match public.get::<PublicConfig>("/api/config").await {
        Ok(config) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "server.reachable",
                "pass",
                format!("Reached {server} (server {}).", config.server_version),
            );
            config
        }
        Err(err) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "server.reachable",
                "failure",
                format!("{err:#}"),
            );
            return write_doctor_report(output, checks, counts, actions);
        }
    };
    push_doctor_check(
        &mut checks,
        &mut counts,
        "server.api_compatible",
        if public_config.api_version == 3 {
            "pass"
        } else {
            "failure"
        },
        format!(
            "Server API version is {} (CLI expects 3).",
            public_config.api_version
        ),
    );
    let cli_compatible = validate_cli_version(
        &public_config.minimum_cli_version,
        env!("CARGO_PKG_VERSION"),
    );
    let cli_is_compatible = cli_compatible.is_ok();
    let cli_compatibility_message = match &cli_compatible {
        Ok(()) => format!(
            "CLI {} meets the server minimum {}.",
            env!("CARGO_PKG_VERSION"),
            public_config.minimum_cli_version
        ),
        Err(err) => err.to_string(),
    };
    push_doctor_check(
        &mut checks,
        &mut counts,
        "server.cli_compatible",
        if cli_is_compatible { "pass" } else { "failure" },
        cli_compatibility_message,
    );
    if !cli_is_compatible {
        actions.push(serde_json::json!({
            "id": "upgrade-cli",
            "priority": 1,
            "reason": "cli_below_server_minimum",
            "commands": upgrade_commands(),
            "mutates": "installed_binary",
            "requires_user_input": false,
        }));
    }
    let expected_protocol = String::from_utf8_lossy(devsite_proto::ALPN);
    push_doctor_check(
        &mut checks,
        &mut counts,
        "server.daemon_protocol",
        if public_config.daemon_protocol == expected_protocol {
            "pass"
        } else {
            "failure"
        },
        format!(
            "Server daemon protocol is {}.",
            public_config.daemon_protocol
        ),
    );

    match public.get::<PubKeyResponse>("/api/pubkey").await {
        Ok(remote) => {
            let matches = config.control_plane_key.as_deref() == Some(remote.public_key.as_str());
            push_doctor_check(
                &mut checks,
                &mut counts,
                "server.signing_key_matches",
                if matches { "pass" } else { "failure" },
                if matches {
                    "The server signing key matches the key pinned at login."
                } else {
                    "The server signing key differs from the key pinned at login; verify the control-plane origin before logging in again."
                },
            );
            if !matches {
                actions.push(serde_json::json!({
                    "id": "verify-signing-key-change",
                    "priority": 1,
                    "reason": "server_signing_key_changed",
                    "commands": [["devsite", "login", "TICKET"]],
                    "mutates": "pinned_trust_and_machine_credential",
                    "requires_user_input": true,
                }));
            }
        }
        Err(err) => push_doctor_check(
            &mut checks,
            &mut counts,
            "server.signing_key_matches",
            "failure",
            format!("{err:#}"),
        ),
    }
    match config.verifying_key() {
        Ok(_) => push_doctor_check(
            &mut checks,
            &mut counts,
            "config.signing_key",
            "pass",
            "The pinned signing key is valid Ed25519 material.",
        ),
        Err(err) => push_doctor_check(
            &mut checks,
            &mut counts,
            "config.signing_key",
            "failure",
            format!("{err:#}"),
        ),
    }

    let Some(credential) = config.machine_credential.clone() else {
        push_doctor_check(
            &mut checks,
            &mut counts,
            "auth.credential_valid",
            "failure",
            "No machine credential is configured.",
        );
        actions.push(serde_json::json!({
            "id": "login",
            "priority": 1,
            "reason": "machine_credential_missing",
            "commands": [["devsite", "login", "TICKET"]],
            "mutates": "local_and_remote_identity",
            "requires_user_input": true,
        }));
        return write_doctor_report(output, checks, counts, actions);
    };
    let api = ControlPlane::new(server, Some(credential));
    match api.get::<MeResponse>("/api/me").await {
        Ok(me) => push_doctor_check(
            &mut checks,
            &mut counts,
            "auth.credential_valid",
            "pass",
            format!(
                "The machine credential is valid for @{}.",
                me.handle.as_deref().unwrap_or("(no handle)")
            ),
        ),
        Err(err) => {
            push_doctor_check(
                &mut checks,
                &mut counts,
                "auth.credential_valid",
                "failure",
                format!("{err:#}"),
            );
            actions.push(serde_json::json!({
                "id": "login",
                "priority": 1,
                "reason": "machine_credential_invalid",
                "commands": [["devsite", "login", "TICKET"]],
                "mutates": "local_and_remote_identity",
                "requires_user_input": true,
            }));
            return write_doctor_report(output, checks, counts, actions);
        }
    }

    match api.get::<DaemonInfo>("/api/daemon").await {
        Ok(info) => {
            let bound_matches =
                endpoint_id.as_deref() == Some(info.credential_endpoint_id.as_str());
            push_doctor_check(
                &mut checks,
                &mut counts,
                "identity.credential_binding",
                if bound_matches { "pass" } else { "failure" },
                if bound_matches {
                    "The machine credential is bound to this endpoint identity."
                } else {
                    "The machine credential is bound to a different endpoint identity."
                },
            );
            let registered_matches_local =
                info.registered_endpoint_id.as_deref() == endpoint_id.as_deref();
            let registration_status = if info.registered_endpoint_id.is_none() {
                if config.resources.is_empty() {
                    "pass"
                } else {
                    "warning"
                }
            } else if registered_matches_local {
                "pass"
            } else if daemon_running {
                "failure"
            } else {
                "warning"
            };
            push_doctor_check(
                &mut checks,
                &mut counts,
                "daemon.registration",
                registration_status,
                match info.registered_endpoint_id {
                    None => "No daemon endpoint has been registered yet.".to_string(),
                    Some(ref registered) if Some(registered.as_str()) == endpoint_id.as_deref() => {
                        "The account is registered to this endpoint identity.".to_string()
                    }
                    Some(registered) if info.registration_matches_credential => format!(
                        "The account is registered to the credential endpoint ({registered}), but that is not this machine's local identity."
                    ),
                    Some(registered) => format!(
                        "The account is registered to another endpoint identity ({registered})."
                    ),
                },
            );
            if bound_matches && !registered_matches_local && !config.resources.is_empty() {
                actions.push(serde_json::json!({
                    "id": "register-this-endpoint",
                    "priority": 2,
                    "reason": "account_registered_to_another_endpoint",
                    "commands": daemon_start_commands(),
                    "mutates": "account_daemon_registration",
                    "requires_user_input": true,
                }));
            }
        }
        Err(err) => push_doctor_check(
            &mut checks,
            &mut counts,
            "identity.credential_binding",
            "failure",
            format!("{err:#}"),
        ),
    }

    match api.get::<ResourceListing>("/api/resources").await {
        Ok(listing) => {
            let remote = listing
                .resources
                .iter()
                .map(|resource| resource.resource_id.as_str())
                .collect::<HashSet<_>>();
            let local_only = config
                .resources
                .iter()
                .filter(|resource| !remote.contains(resource.resource_id.to_string().as_str()))
                .map(|resource| resource.name.clone())
                .collect::<Vec<_>>();
            let visibility_mismatches = config
                .resources
                .iter()
                .filter_map(|local| {
                    listing
                        .resources
                        .iter()
                        .find(|remote| remote.resource_id == local.resource_id.to_string())
                        .filter(|remote| remote.visibility != visibility_str(local.visibility))
                        .map(|_| local.name.clone())
                })
                .collect::<Vec<_>>();
            let reconciled = local_only.is_empty() && visibility_mismatches.is_empty();
            push_doctor_check(
                &mut checks,
                &mut counts,
                "resources.reconciled",
                if reconciled { "pass" } else { "warning" },
                if reconciled {
                    "Every local service mapping has a remote resource.".to_string()
                } else {
                    format!(
                        "Local-only services: {}; visibility mismatches: {}.",
                        if local_only.is_empty() {
                            "none".to_string()
                        } else {
                            local_only.join(", ")
                        },
                        if visibility_mismatches.is_empty() {
                            "none".to_string()
                        } else {
                            visibility_mismatches.join(", ")
                        }
                    )
                },
            );
            for name in local_only {
                actions.push(serde_json::json!({
                    "id": format!("remove-local-only-{name}"),
                    "priority": 2,
                    "reason": "missing_remote_resource",
                    "commands": [["devsite", "service", "remove", name]],
                    "mutates": "local_config",
                    "requires_user_input": false,
                }));
            }
        }
        Err(err) => push_doctor_check(
            &mut checks,
            &mut counts,
            "resources.reconciled",
            "failure",
            format!("{err:#}"),
        ),
    }

    write_doctor_report(output, checks, counts, actions)
}

fn write_doctor_report(
    output: Output,
    checks: Vec<serde_json::Value>,
    counts: [u64; 4],
    actions: Vec<serde_json::Value>,
) -> Result<()> {
    let report = serde_json::json!({
        "healthy": counts[2] == 0,
        "summary": {
            "pass": counts[0],
            "warning": counts[1],
            "failure": counts[2],
            "skipped": counts[3],
        },
        "checks": checks,
        "actions": actions,
    });
    if output.json {
        output.success("doctor", report);
    } else {
        println!(
            "doctor: {} pass, {} warning, {} failure, {} skipped",
            counts[0], counts[1], counts[2], counts[3]
        );
        for check in report["checks"].as_array().unwrap_or(&Vec::new()) {
            println!(
                "  {:<7} {:<32} {}",
                check["status"].as_str().unwrap_or("unknown"),
                check["id"].as_str().unwrap_or("check"),
                check["message"].as_str().unwrap_or("")
            );
        }
    }
    Ok(())
}

fn status(paths: &Paths, output: Output) -> Result<()> {
    let config = paths.load_config()?;
    let daemon_running = paths.daemon_running()?;
    let endpoint_id = std::fs::read_to_string(paths.identity_public())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
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
                "identity": {
                    "public_path": paths.identity_public(),
                    "endpoint_id": endpoint_id,
                },
                "authentication": {
                    "configured": config.machine_credential.is_some(),
                },
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

#[cfg(target_os = "macos")]
fn daemon_start_commands() -> serde_json::Value {
    serde_json::json!([
        ["brew", "services", "start", "devsite"],
        ["devsite", "daemon", "run"]
    ])
}

#[cfg(target_os = "linux")]
fn daemon_start_commands() -> serde_json::Value {
    serde_json::json!([
        ["systemctl", "--user", "enable", "--now", "devsite.service"],
        ["devsite", "daemon", "run"]
    ])
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn daemon_start_commands() -> serde_json::Value {
    serde_json::json!([["devsite", "daemon", "run"]])
}

#[cfg(target_os = "macos")]
fn upgrade_commands() -> serde_json::Value {
    serde_json::json!([["brew", "upgrade", "devsite"]])
}

#[cfg(not(target_os = "macos"))]
fn upgrade_commands() -> serde_json::Value {
    serde_json::json!([])
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
    let proof = endpoint_proof(&secret_key);
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
    // clients resolve it from there. The control plane holds permissions; it is
    // not a directory service.
    let api = ControlPlane::new(&server_url, token);
    api.put_empty("/api/daemon", &serde_json::json!({ "proof": proof }))
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
    let authorization_api = api.clone();
    tokio::select! {
        result = Arc::clone(&daemon).serve() => result?,
        result = reload_config(reload_paths, Arc::clone(&daemon), output) => result?,
        result = sync_authorizations(authorization_api, Arc::clone(&daemon)) => result?,
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

async fn sync_authorizations(api: ControlPlane, daemon: Arc<Daemon>) -> Result<()> {
    const REFRESH: Duration = Duration::from_secs(2);
    const STALE_LEASE: Duration = Duration::from_secs(15);

    let mut interval = tokio::time::interval(REFRESH);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_success = Instant::now();
    let mut failed_closed = false;

    loop {
        interval.tick().await;
        match api
            .get::<AuthorizationListing>("/api/daemon/authorizations")
            .await
        {
            Ok(listing) => {
                let allowed = listing
                    .authorizations
                    .into_iter()
                    .map(|entry| {
                        Ok((
                            entry.viewer_id.parse::<AccountId>()?,
                            entry.resource_id.parse::<ResourceId>()?,
                        ))
                    })
                    .collect::<Result<HashSet<_>>>()?;
                let revoked = daemon.replace_authorizations(allowed).await;
                if revoked > 0 {
                    tracing::info!(revoked, "closed streams whose authorization was revoked");
                }
                last_success = Instant::now();
                failed_closed = false;
            }
            Err(err) => {
                tracing::warn!("could not refresh active-stream authorizations: {err:#}");
                if last_success.elapsed() >= STALE_LEASE {
                    let revoked = daemon.revoke_all_active().await;
                    if !failed_closed || revoked > 0 {
                        tracing::warn!(
                            revoked,
                            "authorization lease expired; closed active streams"
                        );
                    }
                    failed_closed = true;
                }
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::validate_cli_version;

    #[test]
    fn cli_version_validation_accepts_equal_or_newer_versions() {
        assert!(validate_cli_version("0.3.0", "0.3.0").is_ok());
        assert!(validate_cli_version("0.3.0", "0.4.0").is_ok());
    }

    #[test]
    fn cli_version_validation_rejects_older_or_invalid_versions() {
        assert!(validate_cli_version("0.3.1", "0.3.0")
            .unwrap_err()
            .to_string()
            .contains("server requires CLI 0.3.1 or newer"));
        assert!(validate_cli_version("not-a-version", "0.3.0").is_err());
    }
}
