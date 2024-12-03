use ::time::Duration;
use axum::{body::Body, extract::Request, response::Response};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use base64ct::{Base64, Encoding};
use std::collections::HashSet;

pub fn authenticate(credentials: &HashSet<&str>, request: &Request) -> Response {
    // Get headers.
    let headers = request.headers();

    // Check session cookie.
    let cookies = CookieJar::from_headers(headers);
    if let Some(cookie) = cookies.get("session") {
        let session = cookie.value();
        if credentials.contains(session) {
            // Session cookie is valid.
            // Reset the expiration timer by setting the cookie again.
            return success(session);
        }
    }

    // Check if authorization header is present.
    let auth = headers.get("Authorization");
    if let None = auth {
        return unauthorized();
    }

    // Check if authorization header is well-formed.
    let auth = auth.unwrap().to_str().unwrap();
    let split = auth.split_once(' ');
    if let None = split {
        return bad_request();
    }

    // Check if authorization header is basic.
    let (name, contents) = split.unwrap();
    if name != "Basic" {
        return bad_request();
    }

    // Decode contents.
    let decoded = Base64::decode_vec(contents).unwrap();
    let session = std::str::from_utf8(decoded.as_slice()).unwrap();

    // Check if credentials are valid.
    if !credentials.contains(session) {
        return unauthorized();
    }

    // Set session cookie.
    success(session)
}

/// Returns a `200 OK` response with a session cookie.
fn success(credentials: &str) -> Response {
    // Create cookie.
    let cookie = Cookie::build(("session", credentials))
        .http_only(true)
        .max_age(Duration::days(400))
        .path("/")
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .secure(true)
        .to_string();

    // Create response.
    Response::builder()
        .status(200)
        .header("set-cookie", cookie)
        .body(Body::empty())
        .unwrap()
}

/// Returns a `400 Bad Request` response.
fn bad_request() -> Response {
    Response::builder()
        .status(400)
        // Meme response from WordPress.
        .body("Error: Error establishing a database connection.".into())
        .unwrap()
}

/// Returns a `401 Unauthorized` response.
fn unauthorized() -> Response {
    Response::builder()
        .status(401)
        .header("WWW-Authenticate", "Basic realm=\"example\"")
        // Slightly nicer looking response.
        .body("<html><strong>Please</strong> sign in.</html>".into())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    const CREDENTIALS: &str = "user:pass";
    const BAD_CREDENTIALS: &str = "bad:pass";

    const COOKIE: &str =
        "session=user:pass; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=34560000";

    fn get_hashset() -> HashSet<&'static str> {
        [CREDENTIALS].iter().cloned().collect()
    }

    fn get_session_cookie(response: &Response) -> String {
        response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn test_no_credentials() {
        let request: Request<Body> = Request::builder().body("".into()).unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `401 Unauthorized` response.
        assert_eq!(401, response.status());
    }

    #[test]
    fn test_good_credentials_in_cookie() {
        let request: Request<Body> = Request::builder()
            .header("Cookie", format!("session={}", CREDENTIALS))
            .body("".into())
            .unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `200 OK` response.
        assert_eq!(200, response.status());

        // Expect a good cookie.
        let cookie = get_session_cookie(&response);
        assert_eq!(COOKIE, cookie);
    }

    #[test]
    fn test_good_credentials_in_header() {
        let request: Request<Body> = Request::builder()
            .header(
                "Authorization",
                format!("Basic {}", Base64::encode_string(CREDENTIALS.as_bytes())),
            )
            .body("".into())
            .unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `200 OK` response.
        assert_eq!(200, response.status());

        // Expect a good cookie.
        let cookie = get_session_cookie(&response);
        assert_eq!(COOKIE, cookie);
    }

    #[test]
    fn test_bad_credentials_in_header() {
        let request: Request<Body> = Request::builder()
            .header(
                "Authorization",
                format!(
                    "Basic {}",
                    Base64::encode_string(BAD_CREDENTIALS.as_bytes())
                ),
            )
            .body("".into())
            .unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `401 Unauthorized` response.
        assert_eq!(401, response.status());
    }

    #[test]
    fn test_non_basic_credentials_in_header() {
        let request: Request<Body> = Request::builder()
            .header(
                "Authorization",
                format!("Advanced {}", Base64::encode_string(CREDENTIALS.as_bytes())),
            )
            .body("".into())
            .unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `400 Bad Request` response.
        assert_eq!(400, response.status());
    }

    #[test]
    fn test_malformed_credentials_in_header() {
        let request: Request<Body> = Request::builder()
            .header(
                "Authorization",
                format!("Basic{}", Base64::encode_string(CREDENTIALS.as_bytes())),
            )
            .body("".into())
            .unwrap();
        let response = authenticate(&get_hashset(), &request);

        // Expect a `400 Bad Request` response.
        assert_eq!(400, response.status());
    }
}
