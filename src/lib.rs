mod authenticate;

use authenticate::authenticate;
use axum::{extract::Request, response::Response};
use futures_util::future::BoxFuture;
use std::{
    collections::HashSet,
    task::{Context, Poll},
};
use tower::{Layer, Service};

/// A layer that adds basic authentication to a service.
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

/// Disable coverage for now.
/// Not sure how to mock service w/ correct trait bounds.
#[cfg(not(tarpaulin_include))]
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
        let authentication_response = authenticate(&self.credentials, &request);
        let future = self.inner.call(request);

        Box::pin(async {
            // Handle authentication issues.
            if authentication_response.status() != 200 {
                return Ok(authentication_response);
            }

            // Add session cookie.
            let mut service_response = future.await?;
            add_session_cookie(authentication_response, &mut service_response);

            Ok(service_response)
        })
    }
}

/// Adds session cookie from an authentication response to a service response.
fn add_session_cookie(authentication_response: Response, service_response: &mut Response) {
    let value = authentication_response
        .headers()
        .get("set-cookie")
        .unwrap()
        .clone();

    service_response.headers_mut().append("set-cookie", value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    const CREDENTIALS: &str = "user:pass";

    #[test]
    fn test_basic_auth_layer_fn() {
        // Create wrapped service.
        let basic_auth = BasicAuth::new(&[CREDENTIALS]);
        let tower_service = tower::service_fn(|_: Request<Body>| async {
            Ok::<Response<Body>, axum::Error>(Response::new(Body::empty()))
        });
        let new_service = basic_auth.layer(tower_service);

        // Verify credentials are set.
        assert!(new_service.credentials.contains(CREDENTIALS));
    }

    #[test]
    fn test_add_session_cookie() {
        // Create service response.
        let mut service_response = Response::new(Body::empty());

        // Add session cookie from an authentication response.
        let authentication_response = Response::builder()
            .header("set-cookie", "session=user:pass")
            .body(Body::empty())
            .unwrap();
        add_session_cookie(authentication_response, &mut service_response);

        // Verify session cookie was added to service response.
        let cookie = service_response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cookie, "session=user:pass");
    }
}
