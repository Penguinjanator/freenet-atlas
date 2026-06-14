#![allow(non_snake_case)]
//! Atlas Discover: a read-only front door to Freenet. Connects to the local node
//! over the WebSocket command API, GET+SUBSCRIBEs the index contract, and renders
//! browse + client-side search + Open. No identity, no writes, no delegate.

use std::cell::RefCell;

use atlas_common::{IndexEntry, IndexState, Kind, Locator};
use dioxus::prelude::*;
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, Error, HostResponse, WebApi,
};
use freenet_stdlib::prelude::ContractInstanceId;
use wasm_bindgen_futures::spawn_local;

/// The index contract instance id. Baked in at build time; overridable so the
/// same UI can target a test index. Default is the local-dev index.
const INDEX_ID: &str = match option_env!("ATLAS_INDEX_ID") {
    Some(s) => s,
    None => "CJUR37WSMxV7C1yhrr3xSgjnrJT5yuvQGFNcgvSnsvg",
};

static STATE: GlobalSignal<Option<IndexState>> = Signal::global(|| None);
static STATUS: GlobalSignal<String> = Signal::global(|| "connecting…".to_string());

thread_local! {
    static API: RefCell<Option<WebApi>> = const { RefCell::new(None) };
}

const CSS: &str = r#"
:root { --bg:#fff; --fg:#1a1a1a; --dim:#6b7280; --line:#e5e7eb; --card:#fafafa; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0f1115; --fg:#e8e8ea; --dim:#9ca3af; --line:#262a31; --card:#161922; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif; }
.wrap { max-width:960px; margin:0 auto; padding:2rem 1.25rem; }
header h1 { margin:0; font-weight:650; letter-spacing:-0.02em; }
.tag { color:var(--dim); margin:.15rem 0 1.25rem; }
.search { width:100%; padding:.7rem .9rem; font-size:1rem; color:var(--fg);
  background:var(--card); border:1px solid var(--line); border-radius:8px; outline:none; }
.search:focus { border-color:var(--dim); }
.status { color:var(--dim); font-size:.8rem; margin:.6rem 0 1.25rem; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(260px,1fr)); gap:.9rem; }
.card { border:1px solid var(--line); border-radius:10px; padding:1rem; background:var(--card);
  display:flex; flex-direction:column; min-height:140px; }
.card-top { display:flex; justify-content:space-between; align-items:center; margin-bottom:.4rem; }
.kind { font-size:.65rem; text-transform:uppercase; letter-spacing:.06em; color:var(--dim);
  border:1px solid var(--line); border-radius:4px; padding:.05rem .35rem; }
.star { color:var(--dim); }
.card h3 { margin:.1rem 0 .35rem; font-size:1.02rem; }
.snip { color:var(--dim); font-size:.88rem; margin:0 0 .6rem; flex:1; }
.tags { display:flex; flex-wrap:wrap; gap:.3rem; margin-bottom:.7rem; }
.t { font-size:.68rem; color:var(--dim); border:1px solid var(--line); border-radius:4px; padding:.02rem .3rem; }
.open { align-self:flex-start; font-size:.82rem; text-decoration:none; color:var(--fg);
  border:1px solid var(--line); border-radius:6px; padding:.3rem .6rem; }
.open:hover { border-color:var(--dim); }
.empty { color:var(--dim); padding:2rem 0; }
"#;

fn main() {
    #[cfg(target_arch = "wasm32")]
    std::panic::set_hook(Box::new(|info| {
        web_sys::console::error_1(&format!("atlas panic: {info}").into());
    }));
    launch(App);
}

fn App() -> Element {
    use_hook(|| connect());
    let mut query = use_signal(String::new);
    let q = query().to_lowercase();

    let entries: Vec<IndexEntry> = match STATE.read().as_ref() {
        Some(state) => {
            let mut v: Vec<IndexEntry> = state.live_entries().cloned().collect();
            v.sort_by(|a, b| b.featured.cmp(&a.featured).then(b.added_at.cmp(&a.added_at)));
            v.into_iter().filter(|e| matches_query(e, &q)).collect()
        }
        None => Vec::new(),
    };

    rsx! {
        style { dangerous_inner_html: CSS }
        div { class: "wrap",
            header {
                h1 { "Atlas" }
                p { class: "tag", "Discover Freenet" }
            }
            input {
                class: "search",
                placeholder: "Search apps, sites, and more…",
                value: "{query}",
                oninput: move |e| query.set(e.value()),
            }
            div { class: "status", "{STATUS}" }
            if entries.is_empty() {
                div { class: "empty",
                    if STATE.read().is_some() { "Nothing matches." } else { "Loading…" }
                }
            } else {
                div { class: "grid",
                    for e in entries {
                        EntryCard { key: "{e.subject_id.as_str()}", entry: e }
                    }
                }
            }
        }
    }
}

#[component]
fn EntryCard(entry: IndexEntry) -> Element {
    let external = matches!(entry.locator, Locator::External { .. });
    let href = open_href(&entry.locator);
    rsx! {
        div { class: "card",
            div { class: "card-top",
                span { class: "kind", "{kind_label(entry.kind)}" }
                if entry.featured {
                    span { class: "star", "★" }
                }
            }
            h3 { "{entry.title}" }
            p { class: "snip", "{entry.snippet}" }
            if !entry.tags.is_empty() {
                div { class: "tags",
                    for t in entry.tags.iter() {
                        span { class: "t", "{t}" }
                    }
                }
            }
            a {
                class: "open",
                href: "{href}",
                target: if external { "_blank" } else { "_self" },
                "Open ↗"
            }
        }
    }
}

fn connect() {
    let url = match ws_url() {
        Some(u) => u,
        None => return,
    };
    let ws = match web_sys::WebSocket::new(&url) {
        Ok(w) => w,
        Err(_) => {
            *STATUS.write() = "websocket error".to_string();
            return;
        }
    };
    let api = WebApi::start(
        ws,
        |res| match res {
            Ok(HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. })) => {
                match ciborium::de::from_reader::<IndexState, _>(state.as_ref()) {
                    Ok(st) => {
                        *STATE.write() = Some(st);
                        *STATUS.write() = "ready".to_string();
                    }
                    Err(e) => *STATUS.write() = format!("decode error: {e}"),
                }
            }
            Ok(HostResponse::ContractResponse(ContractResponse::UpdateNotification { .. })) => {
                spawn_local(request_index());
            }
            Ok(HostResponse::ContractResponse(ContractResponse::NotFound { .. })) => {
                // The index may not be hosted on a reachable peer yet (cross-node
                // propagation). Retry rather than hang on "Loading…".
                *STATUS.write() = "looking for the index…".to_string();
                gloo_timers::callback::Timeout::new(4000, || spawn_local(request_index())).forget();
            }
            Ok(_) => {}
            Err(e) => {
                *STATUS.write() = format!("error: {e}");
                gloo_timers::callback::Timeout::new(5000, || spawn_local(request_index())).forget();
            }
        },
        |_e: Error| {},
        || {
            *STATUS.write() = "connected".to_string();
            spawn_local(request_index());
        },
    );
    API.with(|a| *a.borrow_mut() = Some(api));
}

async fn request_index() {
    let id = match INDEX_ID.parse::<ContractInstanceId>() {
        Ok(i) => i,
        Err(_) => {
            *STATUS.write() = "bad index id".to_string();
            return;
        }
    };
    let req = ClientRequest::ContractOp(ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe: true,
        blocking_subscribe: false,
    });
    let api = API.with(|a| a.borrow_mut().take());
    if let Some(mut api) = api {
        let _ = api.send(req).await;
        API.with(|a| *a.borrow_mut() = Some(api));
    }
}

fn ws_url() -> Option<String> {
    let win = web_sys::window()?;
    let loc = win.location();
    let proto = loc.protocol().unwrap_or_else(|_| "http:".to_string());
    let host = loc.host().unwrap_or_default();
    let ws_proto = if proto == "https:" { "wss:" } else { "ws:" };
    let mut url = format!("{ws_proto}//{host}/v1/contract/command?encodingProtocol=native");
    if let Ok(tok) = js_sys::Reflect::get(&win, &"__FREENET_AUTH_TOKEN__".into()) {
        if let Some(t) = tok.as_string() {
            if !t.is_empty() {
                url.push_str(&format!("&authToken={t}"));
            }
        }
    }
    Some(url)
}

fn open_href(loc: &Locator) -> String {
    match loc {
        Locator::Freenet { contract_id, path } => {
            format!("/v1/contract/web/{contract_id}{path}")
        }
        Locator::External { url } => url.clone(),
    }
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::App => "app",
        Kind::Site => "site",
        Kind::External => "web",
    }
}

fn matches_query(e: &IndexEntry, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    e.title.to_lowercase().contains(q)
        || e.snippet.to_lowercase().contains(q)
        || e.tags.iter().any(|t| t.to_lowercase().contains(q))
}
