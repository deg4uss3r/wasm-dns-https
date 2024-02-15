use bytes::Buf;
use dns_message_parser::question;
use fastly::http::{header, Method, StatusCode};
use fastly::{Backend, mime, Body, Error, Request, Response};

use base64::prelude::*;
use std::str;
use std::time::Duration;

const BLOCKLIST: &[&str] = &["facebook.com"];
const GOOGLEDNS: &str = "https://dns.google/resolve?name=";
const DNSBINARY: &str = "&ct=application/dns-message";
const BACKEND: &str = "hosfelt_dev";

#[fastly::main]
fn main(req: Request) -> Result<Response, Error> {
    // Dynamic backend setup
    // This needs activated on the service, I'd like to avoid that for now 
    /*let backend = Backend::builder("my_backend", "http-me.glitch.me")
    .override_host("http-me.glitch.me")
    .connect_timeout(Duration::from_secs(1))
    .first_byte_timeout(Duration::from_secs(15))
    .between_bytes_timeout(Duration::from_secs(10))
    .enable_ssl()
    .finish()?;*/

    // Log service version
    println!(
        "FASTLY_SERVICE_VERSION: {}",
        std::env::var("FASTLY_SERVICE_VERSION").unwrap_or_else(|_| String::new())
    );

    match req.get_method() {
        // Block requests with unexpected methods
        &Method::HEAD
        | &Method::OPTIONS
        | &Method::CONNECT
        | &Method::TRACE
        | &Method::PUT
        | &Method::PATCH
        | &Method::DELETE => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, POST")
                .with_body_text_plain("This method is not allowed\n"))
        }

        // Let any other requests through in this case literally only GET or POST
        _ => (),
    };

    match req.get_path() {
        x if x.starts_with("/dns-query") => {
            let base64_url = req.get_query_parameter("dns").unwrap().to_owned();
            let dns_request_wire = BASE64_URL_SAFE_NO_PAD.decode(base64_url).unwrap();
            let dns_request =
                dns_message_parser::Dns::decode(dns_request_wire.clone().into()).unwrap();
            let urls = dns_request
                .questions
                .iter()
                .map(|question| format!("{}", question.domain_name))
                .collect::<Vec<String>>();

            // this is not possible yet in wasmtime on Fastly's Compute
            /*let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.send_to(&dns_request_wire, "8.8.8.8:53").unwrap();

            let mut buf = [0; 2048];
            match socket.recv_from(&mut buf) {
                Ok(received) => {
                    let mut body = Body::new();
                    body.write_bytes(&buf);


                }
                Err(e) => Ok(Response::from_status(StatusCode::OK)
                    .with_content_type(mime::TEXT_HTML_UTF_8)
                    .with_body(include_str!("./404.html"))),
            }*/

            // so for now we'll use Google's DNS-over-https as in intermediary 
            // I've picked the JSON API because it has more options availble 
            // https://developers.google.com/speed/public-dns/docs/doh/json
            // https://dns.google/resolve?name=www.fastly.com.&ct=application/dns-message
            //TODO hook up Google's API

            // For now only do one question
            let req = format!("{}{}{}", GOOGLEDNS, urls[0], DNSBINARY);

           println!("{req}"); 

            let mut response = Request::get(req).send(BACKEND)?;
            println!("resp: {response:?}");
            let body = response.take_body_bytes();
            let content_length = response.get_content_length();

            println!("{body:?}");

            Ok(Response::from_status(StatusCode::OK)
            .with_header("Content-Type", "application/dns-message")
            .with_header("Content-Length", format!("{}", content_length.unwrap_or(0)))
            .with_header("Cache-Control", "max-age=3709")
            .with_body(body))
            
        },
        _ => Ok(Response::from_status(StatusCode::OK)
            .with_content_type(mime::TEXT_HTML_UTF_8)
            .with_body(include_str!("./404.html"))),
    }
}
