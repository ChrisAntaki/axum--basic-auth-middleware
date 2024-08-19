# Axum Basic Auth

NOTE: This is an unaudited work in progress.

This crate provides [Basic Auth](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication) middleware for the Axum web framework.

## Usage

1. Add crate.

```sh
cargo add --git https://github.com/ChrisAntaki/axum--basic-auth-middleware
```

2. Add layer.

```rust
let router = Router::new()
  .nest_service("/", ServeDir::new("static"))
  .route_layer(BasicAuth::new(&["admin:password"])); // Define a list of credentials formatted as "user:pass".
```
