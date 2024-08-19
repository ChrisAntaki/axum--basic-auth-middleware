use ::time::Duration;
use axum::{
    extract::Request,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use base64ct::{Base64, Encoding};
use futures_util::future::BoxFuture;
use std::{
    collections::HashSet,
    task::{Context, Poll},
};
use tower::{Layer, Service};

#[derive(Clone)]
pub struct BasicAuth {
    credentials: HashSet<&'static str>,
}

impl BasicAuth {
    pub fn new(credentials: &[&'static str]) -> Self {
        let credentials = credentials.iter().cloned().collect();
        BasicAuth { credentials }
    }
}

impl<S> Layer<S> for BasicAuth {
    type Service = BasicAuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BasicAuthMiddleware {
            inner,
            credentials: self.credentials.clone(),
        }
    }
}

#[derive(Clone)]
pub struct BasicAuthMiddleware<S> {
    inner: S,
    credentials: HashSet<&'static str>,
}

impl<S> Service<Request> for BasicAuthMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // `BoxFuture` is a type alias for `Pin<Box<dyn Future + Send + 'a>>`
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Authenticate the request.
        if let Some(response) = self.authenticate(&request) {
            return Box::pin(async move { Ok(response) });
        }

        // Call the inner service.
        let future = self.inner.call(request);
        Box::pin(async move {
            let response: Response = future.await?;
            Ok(response)
        })
    }
}

impl<S> BasicAuthMiddleware<S> {
    fn authenticate(&self, request: &Request) -> Option<Response> {
        // Get headers.
        let headers = request.headers();

        // Check session cookie.
        let cookies = CookieJar::from_headers(headers);
        if let Some(cookie) = cookies.get("session") {
            if self.credentials.contains(cookie.value()) {
                // Session cookie is valid.
                return None;
            }
        }

        // Check if the header is present.
        let auth = headers.get("Authorization");
        if let None = auth {
            return unauthorized();
        }

        // Check if the header is well-formed.
        let auth = auth.unwrap().to_str().unwrap();
        let split = auth.split_once(' ');
        if let None = split {
            return bad_request();
        }

        // Check if the header is basic auth.
        let (name, contents) = split.unwrap();
        if name != "Basic" {
            return bad_request();
        }

        // Decode the contents.
        let decoded = Base64::decode_vec(contents).unwrap();
        let decoded = std::str::from_utf8(decoded.as_slice()).unwrap();

        // Check if the credentials are valid.
        if !self.credentials.contains(decoded) {
            return unauthorized();
        }

        // Set session cookie and redirect.
        let cookie = Cookie::build(("session", decoded.to_owned()))
            .same_site(axum_extra::extract::cookie::SameSite::Lax)
            .http_only(true)
            .max_age(Duration::MAX)
            .build();
        let cookies = cookies.add(cookie);
        let path = request.uri().path_and_query().unwrap().as_str();
        let redirect = Redirect::temporary(path);
        let response = (cookies, redirect).into_response();
        Some(response)
    }
}

/// Returns a `400 Bad Request` response.
fn bad_request() -> Option<Response> {
    Some(
        Response::builder()
            .status(400)
            // Meme response from WordPress.
            .body("Error: Error establishing a database connection.".into())
            .unwrap(),
    )
}

/// Returns a `401 Unauthorized` response.
fn unauthorized() -> Option<Response> {
    Some(
        Response::builder()
            .status(401)
            .header("WWW-Authenticate", "Basic realm=\"example\"")
            // Slightly nicer looking response.
            .body("<html><strong>Please</strong> sign in.</html>".into())
            .unwrap(),
    )
}
