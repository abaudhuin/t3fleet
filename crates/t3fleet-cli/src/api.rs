use std::{net::Ipv4Addr, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Method, RequestBuilder};
use serde::de::DeserializeOwned;
use t3fleet_protocol::ErrorResponse;
use url::{Host, Url};

pub struct Api {
    client: Client,
    base: Url,
}

impl Api {
    pub fn new(raw_url: &str, allow_insecure_http: bool) -> Result<Self> {
        let base = Url::parse(raw_url).context("invalid fleet server URL")?;
        ensure!(
            matches!(base.scheme(), "http" | "https")
                && base.host().is_some()
                && base.username().is_empty()
                && base.password().is_none()
                && base.query().is_none()
                && base.fragment().is_none(),
            "fleet server URL must be an HTTP(S) base URL without credentials, query or fragment"
        );
        let locally_allowed = match base.host() {
            Some(Host::Domain("localhost")) => true,
            Some(Host::Ipv4(ip)) => {
                let [a, b, ..] = ip.octets();
                ip == Ipv4Addr::LOCALHOST || (a == 100 && (64..=127).contains(&b))
            }
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        ensure!(
            base.scheme() == "https" || locally_allowed || allow_insecure_http,
            "plain HTTP enrollment requires loopback, a Tailscale IP, or --allow-insecure-http"
        );
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(900))
            .build()?;
        Ok(Self { client, base })
    }

    pub fn request(&self, method: Method, segments: &[&str]) -> RequestBuilder {
        let mut url = self.base.clone();
        url.path_segments_mut()
            .expect("validated server URL")
            .pop_if_empty()
            .extend(segments);
        self.client.request(method, url)
    }
}

pub async fn send<T: DeserializeOwned>(request: RequestBuilder) -> Result<T> {
    let response = request.send().await.context("calling fleet server")?;
    let status = response.status();
    if !status.is_success() {
        if let Ok(body) = response.json::<ErrorResponse>().await {
            bail!("{}", body.error);
        }
        bail!("fleet server returned HTTP {status}");
    }
    response
        .json()
        .await
        .context("invalid fleet server response")
}
