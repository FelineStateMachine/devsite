//! The browser's Iroh endpoint, exposed to JavaScript.
//!
//! This is a thin wasm-bindgen seam over `devsite-client`. All the protocol logic lives in
//! that crate so it can be tested natively; nothing security-relevant is decided here.

use devsite_client::ViewerEndpoint;
use devsite_proto::capability::SignedCapability;
use wasm_bindgen::prelude::*;

/// Install panic and log hooks. Safe to call more than once.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    tracing_subscriber::fmt()
        .with_writer(tracing_subscriber_wasm::MakeConsoleWriter::default())
        .without_time()
        .with_ansi(false)
        .init();
}

#[wasm_bindgen]
pub struct BrowserEndpoint {
    inner: ViewerEndpoint,
}

#[wasm_bindgen]
impl BrowserEndpoint {
    /// Create an ephemeral endpoint for this tab session and wait until it is relay-ready.
    ///
    /// The key never leaves the browser and is discarded when the page unloads, so a
    /// capability bound to it cannot outlive the session it was issued for.
    #[wasm_bindgen]
    pub async fn create() -> Result<BrowserEndpoint, JsError> {
        let inner = ViewerEndpoint::create()
            .await
            .map_err(|err| JsError::new(&format!("{err:#}")))?;
        Ok(BrowserEndpoint { inner })
    }

    /// This endpoint's public key, to be sent to the control plane so the capability it
    /// issues is bound to this browser and no other.
    #[wasm_bindgen(getter, js_name = endpointId)]
    pub fn endpoint_id(&self) -> String {
        self.inner.endpoint_id().to_string()
    }

    /// Fetch a page from a daemon and return it as text for a sandboxed iframe.
    ///
    /// The daemon is named by its endpoint id and nothing else. Where it can be
    /// reached is iroh's problem: the daemon publishes its own address, and this
    /// endpoint resolves it over HTTPS. The control plane is not asked, and does
    /// not know.
    ///
    /// `capability_b64` comes straight from the control plane and is passed through
    /// opaquely — the browser is a courier for it, not a party to what it says.
    #[wasm_bindgen(js_name = fetchPage)]
    pub async fn fetch_page(
        &self,
        daemon_endpoint_id: String,
        capability_b64: String,
        path: String,
    ) -> Result<String, JsError> {
        let daemon: iroh::EndpointId = daemon_endpoint_id
            .trim()
            .parse()
            .map_err(|_| JsError::new("that does not look like an endpoint id"))?;
        let raw = data_encoding::BASE64URL_NOPAD
            .decode(capability_b64.trim().as_bytes())
            .map_err(|_| JsError::new("capability is not valid base64url"))?;
        let capability = SignedCapability::from_bytes(&raw)
            .map_err(|_| JsError::new("capability is malformed"))?;

        let page = self
            .inner
            .fetch(daemon, capability, &path)
            .await
            .map_err(|err| JsError::new(&format!("{err:#}")))?;

        if page.status != 200 {
            return Err(JsError::new(&format!(
                "local service returned HTTP {}",
                page.status
            )));
        }
        Ok(page.text())
    }
}
