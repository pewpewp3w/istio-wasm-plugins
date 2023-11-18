//use std::rc::Rc;
use std::str;
use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use serde::{Deserialize};
use serde_json;
use base64::{Engine as _, engine::{general_purpose}};
use regex::Regex;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(BasicAuthRoot {
            config: Default::default(),
        })
    });
}}

#[derive(Clone, Deserialize, Debug, Default)]
struct BasicAuthConfig {
    basic_auth_rules: Vec<BasicAuthConfigRule>,
}

#[derive(Clone, Deserialize, Debug, Default)]
struct BasicAuthConfigRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regex: Option<String>,
    request_methods: Vec<String>,
    credentials: Vec<String>,
}

#[derive(Default)]
struct BasicAuth {
    config: BasicAuthConfig,
}

impl Context for BasicAuth {}

impl HttpContext for BasicAuth {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        let path = self.get_http_request_header(":path").unwrap();
        let method = self.get_http_request_header(":method").unwrap();

        for rule in &self.config.basic_auth_rules {
            let is_path_matched = match (&rule.exact, &rule.prefix, &rule.regex) {
                (Some(exact), _, _) if exact == &path => true,
                (_, Some(prefix), _) if path.starts_with(prefix) => true,
                (_, _, Some(regex)) if Regex::new(regex).map_or(false, |re| re.is_match(&path)) => true,
                _ => false,
            };

            if is_path_matched && rule.request_methods.contains(&method) {
                if let Some(auth_header) = self.get_http_request_header("Authorization") {
                    let credentials_b64 = &auth_header["Basic ".len()..];
                    let decoded_credentials = general_purpose::STANDARD.decode(credentials_b64).unwrap_or_default();
                    let credentials_str = String::from_utf8(decoded_credentials).unwrap_or_default();

                    if rule.credentials.contains(&credentials_str) {
                        return Action::Continue;
                    }
                }
                self.send_http_response(
                    401,
                    [].to_vec(),
                    Some("Unauthorized".as_bytes()),
                );
                return Action::Pause;
            }
        }
        Action::Continue
    }
}

#[derive(Default)]
struct BasicAuthRoot {
    config: BasicAuthConfig,
}

impl Context for BasicAuthRoot {}

impl RootContext for BasicAuthRoot {
    fn on_configure(&mut self, _: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            if str::from_utf8(&config_bytes).is_err() {
                return false;
            }
            let conf: BasicAuthConfig = serde_json::from_str(str::from_utf8(&config_bytes).unwrap()).unwrap();

            self.config = conf;
        }
        true
    }

    fn create_http_context(&self, _: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(BasicAuth {
            config: self.config.clone(),
        }))
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

}
