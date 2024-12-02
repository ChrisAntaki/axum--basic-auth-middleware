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
        Box::pin(async move {
            // Handle authentication responses.
            if let Some(authentication_response) = authentication_response {
                return Ok(authentication_response);
            }

            // Handle normal responses.
            let response: Response = future.await?;
            Ok(response)
        })
    }
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
        assert!(new_service.credentials.contains(CREDENTIALS));
    }
}
