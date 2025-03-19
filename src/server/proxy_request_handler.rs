use axum::{
    extract::Request, response::{IntoResponse, Response}
};
use http::StatusCode;
use reqwest::Url;

#[derive(Clone)]
pub struct ProxyRequestHandler {
    host: String,
    http_client: reqwest::Client
}

impl ProxyRequestHandler {
    /// Creates a new `ProxyRequestHandler` with the specified host.
    ///
    /// # Arguments
    ///
    /// * `host` - The proxy host to which requests will be forwarded.
    ///
    /// # Returns
    ///
    /// A new instance of `ProxyRequestHandler`.
    pub fn new(host: String) -> Self {
        Self {
            host,
            http_client: reqwest::Client::new()
        }
    }

    /// Returns the configured proxy host.
    ///
    /// # Returns
    ///
    /// A reference to the proxy host string.
    pub fn host(&self) -> &str {
        &self.host
    }
}

impl ProxyRequestHandler {
    /// Handles proxying of HTTP requests to the configured proxy host.
    ///
    /// This function takes an incoming HTTP request, modifies it to include the appropriate
    /// headers and target URL, and forwards it to the configured proxy host. The response
    /// from the proxy host is then returned to the client.
    ///
    /// # Arguments
    ///
    /// * `request` - The incoming HTTP request to be proxied.
    ///
    /// # Returns
    ///
    /// A `Result<Response, Response>` where:
    /// - `Ok(Response)` contains the successful response from the proxy host.
    /// - `Err(Response)` contains an error response if the request could not be processed.
    ///
    /// # Behavior
    ///
    /// - The function reads the global `PROXY_HOST` to determine the base URL for the proxy.
    /// - It modifies the incoming request's headers to include the `Host` header of the proxy host.
    /// - The request body is wrapped as a stream and forwarded to the proxy host.
    /// - If the request fails to parse or the proxy host is unreachable, appropriate HTTP error
    ///   responses are returned (`400 Bad Request` or `502 Bad Gateway`).
    ///
    /// # Errors
    ///
    /// - Returns `400 Bad Request` if the request URI cannot be parsed.
    /// - Returns `502 Bad Gateway` if the proxy host is unreachable.
    pub async fn handler(&self, request: Request) -> Result<Response, Response> {
        println!("proxy_request: {} {}", request.method(), request.uri());

        let url = Url::options()
            .base_url(Some(&Url::parse(self.host.as_str()).unwrap()))
            .parse(&request.uri().to_string())
            .map_err(|_| (StatusCode::BAD_REQUEST, "Bad Request").into_response())?;

        let mut headers = request.headers().clone();
        headers.insert("Host", url.host_str().unwrap().parse().unwrap());

        let (client, request) = self.http_client
            .request(request.method().clone(), url)
            .headers(headers)
            .body(reqwest::Body::wrap_stream(
                request.into_body().into_data_stream(),
            ))
            .build_split();

        let request = request.map_err(|_| (StatusCode::BAD_REQUEST, "Bad Request").into_response())?;

        let response = client
            .execute(request)
            .await
            .map_err(|_| (StatusCode::BAD_GATEWAY, "Bad Gateway").into_response())?;

        Ok((
            response.status(),
            response.headers().clone(),
            axum::body::Body::new(reqwest::Body::from(response)),
        )
            .into_response())
    }
}
