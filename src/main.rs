use base64::prelude::*;
use fastly::http::{header, request, Method, StatusCode};
use fastly::{cache::simple, mime, Error, Request, Response};
use log::{Level, LevelFilter};
use log_fastly::Logger;
use serde::Serialize;
use time::{format_description::well_known, OffsetDateTime};

use std::time::Duration;
use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    hash::{Hash, Hasher},
    str,
};

const GOOGLEDNS: &str = "https://dns.google/resolve?name=";
const DNSBINARY: &str = "&ct=application/dns-message";
const BACKEND: &str = "dns_google";
const BLOCKLIST: &[u8; 5136805] = include_bytes!("./blocklist.se");

#[derive(Debug, Serialize)]
struct LogFormat {
    time: String,
    data: LogData,
}
#[derive(Debug, Serialize)]
struct LogData {
    id: String,
    level: String,
    fastly_version: u32,
    message: String,
    #[serde(flatten, skip_serializing_if = "HashMap::is_empty")]
    additional_info: HashMap<String, String>,
}

fn log_to_backend(level: Level, message: String, additional_info: HashMap<String, String>) {
    let log_value = LogFormat {
        time: OffsetDateTime::now_utc()
            .format(&well_known::Rfc3339)
            .unwrap(),
        data: LogData {
            id: std::env::var("FASTLY_TRACE_ID").unwrap_or_default(),
            level: level.to_string(),
            fastly_version: std::env::var("FASTLY_SERVICE_VERSION")
                .unwrap_or(String::from("0"))
                .parse()
                .unwrap_or(0),
            message,
            additional_info,
        },
    };

    log::log!(level, "{}", serde_json::to_string(&log_value).unwrap());
}

fn hash<T: Hash>(t: &T) -> String {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish().to_string()
}

//TODO proper error handling
#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Time to start for main
    let start_time = std::time::Instant::now();

    // Initalize Logging
    Logger::builder()
        .max_level(LevelFilter::Debug)
        .default_endpoint("DNSoverHTTPS")
        .echo_stdout(true)
        .init();

    match *req.get_method() {
        Method::GET | Method::POST => {
            match req.get_path() {
                x if x.starts_with("/dns-query") => {
                    // load the block list
                    //TODO perf
                    // I'd like to store this list in a config/KV-store but with the current limits it would not fit
                    // https://docs.fastly.com/products/compute-resource-limits#config-store
                    // could possibly split this up and using a lookup hash
                    let block_list_urls: Vec<&str> = serde_json::from_slice(BLOCKLIST).unwrap();

                    let body = match *req.get_method() {
                        Method::GET => {
                            log_to_backend(
                                Level::Info,
                                "Incoming DNS Request".to_string(),
                                HashMap::from([
                                    ("request_type".to_string(), "GET".to_string()),
                                    (
                                        "duration_since_start".to_string(),
                                        format!("{}", start_time.elapsed().as_micros()),
                                    ),
                                    ("request_url".to_string(), req.get_url_str().to_string()),
                                ]),
                            );

                            let base64_url = req.get_query_parameter("dns").unwrap().to_owned();
                            BASE64_URL_SAFE_NO_PAD.decode(base64_url).unwrap()
                        }
                        Method::POST => {
                            // POST is similar to GET except the request is in the body and it is not base64
                            // encoded but rather bytes on the wire
                            let req_url = req.get_url().to_owned();
                            let body = req.into_body_bytes();

                            log_to_backend(
                                Level::Info,
                                "Incoming DNS Request".to_string(),
                                HashMap::from([
                                    ("request_type".to_string(), "POST".to_string()),
                                    (
                                        "duration_since_start".to_string(),
                                        format!("{}", start_time.elapsed().as_micros()),
                                    ),
                                    ("request_url".to_string(), req_url.to_string()),
                                ]),
                            );

                            body
                        }
                        // We've trapped all other request types in the outer Match statement
                        _ => unreachable!(),
                    };

                    let dns_request = dns_parser::Packet::parse(&body).unwrap();
                    let urls = dns_request
                        .questions
                        .iter()
                        .map(|question| format!("{}", question.qname))
                        .collect::<Vec<String>>();

                    // For now just dead match the domain with that is requested
                    //TODO fixup so subdomain matching etc works
                    if block_list_urls.contains(&urls[0].as_str()) {
                        log_to_backend(
                            Level::Info,
                            "Blocked request".to_string(),
                            HashMap::from([
                                ("url".to_string(), urls[0].clone()),
                                (
                                    "duration_since_start".to_string(),
                                    format!("{}", start_time.elapsed().as_micros()),
                                ),
                            ]),
                        );
                        return Ok(Response::from_status(StatusCode::IM_A_TEAPOT)
                            .with_header("Content-Type", "BLOCKED")
                            .with_header("Cache-Control", "max-age=0")
                            .with_header("x-blocked-on-request", "true"));
                    }

                    // Try to fetch the response from cache, if successful you should have
                    // an optopn with a body in it, if not after you send the request to the service
                    // and the response back to the user, store it in cache for next time
                    // the cache key is just a standard hash of the requested URL
                    let cache = match simple::get(hash(&urls[0])) {
                        Ok(body) => body,
                        Err(_) => None,
                    };

                    if let Some(body) = cache {
                        log_to_backend(
                            Level::Info,
                            "Sent URL from Cache".to_string(),
                            HashMap::from([
                                (
                                    "duration_since_start".to_string(),
                                    format!("{}", start_time.elapsed().as_micros()),
                                ),
                                ("request_url".to_string(), urls[0].clone()),
                            ]),
                        );
                        let bytes = body.into_bytes();

                        return Ok(Response::from_status(StatusCode::OK)
                            .with_header("Content-Type", "application/dns-message")
                            .with_header("Content-Length", format!("{}", bytes.len()))
                            .with_header("Cache-Control", "max-age=3709")
                            .with_header("x-cache-hit", "served from cache")
                            .with_body(bytes));
                    }

                    // For now only do one question, it's possible there's multiple in a single request
                    let req = format!("{}{}{}", GOOGLEDNS, urls[0], DNSBINARY);
                    log_to_backend(
                        Level::Info,
                        "Request sent to Google".to_string(),
                        HashMap::from([
                            ("url".to_string(), req.clone()),
                            (
                                "duration_since_start".to_string(),
                                format!("{}", start_time.elapsed().as_micros()),
                            ),
                        ]),
                    );

                    let response = request::Request::get(req).send(BACKEND)?;
                    let response_status = response.get_status().to_string();
                    let headers = response
                        .get_headers()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
                        .collect::<HashMap<String, String>>();
                    let mut additional_info: HashMap<String, String> = HashMap::from([
                        (
                            "duration_since_start".to_string(),
                            format!("{}", start_time.elapsed().as_micros()),
                        ),
                        ("http_status".to_string(), response_status.clone()),
                        (
                            "http_version".to_string(),
                            format!("{:?}", response.get_version()),
                        ),
                    ]);
                    additional_info.extend(headers);

                    log_to_backend(
                        Level::Info,
                        "Response from Google".to_string(),
                        additional_info,
                    );
                    let bytes = response.into_body().into_bytes();

                    log_to_backend(
                        Level::Info,
                        "Successfully fetched from Google".to_string(),
                        HashMap::from([
                            (
                                "duration_since_start".to_string(),
                                format!("{}", start_time.elapsed().as_micros()),
                            ),
                            ("http_status".to_string(), response_status),
                        ]),
                    );

                    //Store the result if it was not found in cache
                    if cache.is_none() {
                        match simple::get_or_set(
                            hash(&urls[0]),
                            bytes.clone(),
                            Duration::from_secs(2_628_000),
                        ) {
                            Ok(_i) => log_to_backend(
                                Level::Info,
                                "Stored URL Into Cache".to_string(),
                                HashMap::from([
                                    (
                                        "duration_since_start".to_string(),
                                        format!("{}", start_time.elapsed().as_micros()),
                                    ),
                                    ("request_url".to_string(), urls[0].clone()),
                                ]),
                            ),
                            Err(e) => log_to_backend(
                                Level::Warn,
                                "Error Storing URL into Cache".to_string(),
                                HashMap::from([
                                    (
                                        "duration_since_start".to_string(),
                                        format!("{}", start_time.elapsed().as_micros()),
                                    ),
                                    ("request_url".to_string(), urls[0].clone()),
                                    ("error".to_string(), e.to_string()),
                                ]),
                            ),
                        }
                    }

                    log_to_backend(
                        Level::Info,
                        "Sent Response to User".to_string(),
                        HashMap::from([(
                            "duration_since_start".to_string(),
                            format!("{}", start_time.elapsed().as_micros()),
                        )]),
                    );

                    Ok(Response::from_status(StatusCode::OK)
                        .with_header("Content-Type", "application/dns-message")
                        .with_header("Content-Length", format!("{}", bytes.len()))
                        .with_header("Cache-Control", "max-age=3709")
                        .with_header("x-doh-response", "hosfelt.dev")
                        .with_body(bytes))
                }
                _ => {
                    log_to_backend(
                        Level::Warn,
                        "bad url".to_string(),
                        HashMap::from([
                            (
                                "duration_since_start".to_string(),
                                format!("{}", start_time.elapsed().as_micros()),
                            ),
                            ("http_status".to_string(), StatusCode::NOT_FOUND.to_string()),
                            ("requested_url".to_string(), req.get_url().to_string()),
                        ]),
                    );
                    Ok(Response::from_status(StatusCode::NOT_FOUND)
                        .with_content_type(mime::TEXT_HTML_UTF_8)
                        .with_body(include_str!("./404.html")))
                }
            }
        }
        // Block all other request methods that are not GET or POST as per spec
        _ => {
            log_to_backend(
                Level::Warn,
                "bad request method".to_string(),
                HashMap::from([
                    (
                        "duration_since_start".to_string(),
                        format!("{}", start_time.elapsed().as_micros()),
                    ),
                    (
                        "http_status".to_string(),
                        StatusCode::METHOD_NOT_ALLOWED.to_string(),
                    ),
                    (
                        "requested_method".to_string(),
                        req.get_method_str().to_string(),
                    ),
                ]),
            );

            Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, POST")
                .with_body_text_plain("This method is not allowed\n"))
        }
    }
}
