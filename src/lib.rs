/*
 * Copyright (C) 2023 Michael Pacheco
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#![allow(
    clippy::missing_docs_in_private_items,
    clippy::missing_errors_doc,
    clippy::pub_use
)]
// TODO: Documentation

mod schema;

pub mod scrapper_cookie {

    pub use crate::schema::CookieStruct;
    use conversions_rust_lib::ErrToLibErr;
    pub use cookie::Cookie as RawCookie;
    use cookie::SameSite;
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::ops::Add;
    use time::{Duration, OffsetDateTime};
    use url::Url;

    pub(crate) fn build_cookie(raw_str: &str) -> Result<Vec<RawCookie>, liberr::Err> {
        Ok(str_to_json(raw_str)
            .err_to_lib_err(line!())?
            .into_iter()
            .filter_map(struct_to_raw_cookie_chain)
            .collect::<Vec<RawCookie>>())
    }

    /// Builds an Iterator with a RawCookie, Url tuple, for use in insert raw cookie from cookie store
    pub fn build_cookies_url(raw_str: &str) -> impl Iterator<Item = (RawCookie<'_>, Url)> {
        // For now silently fail, may decide later to bubble up these errors later.
        build_raw_cookie_chained(raw_str).filter_map(|cookie| {
            let str = cookie.domain()?;
            let url = format!("https://{str}");
            let url = Url::parse(&url).ok()?;
            Some((cookie, url))
        })
    }

    /// accepts a json with a top level array of cookie objects (represented by the CookieStruct
    ///  in the schema file) and converts to a RawCookie
    /// # Panics
    ///
    /// Will panic if the str is either invalid json or if it is valid, does not follow the schema in schema.rs
    pub fn build_raw_cookie_chained(raw_str: &str) -> Box<dyn Iterator<Item = RawCookie<'_>> + '_> {
        match build_raw_cookie(raw_str) {
            Ok(x) => Box::new(x),
            Err(_) => Box::new(core::iter::empty::<RawCookie>()),
        }
    }
    pub fn build_raw_cookie(
        raw_str: &str,
    ) -> Result<impl Iterator<Item = RawCookie<'_>>, liberr::Err> {
        Ok(str_to_json(raw_str)
            .err_to_lib_err(line!())?
            .into_iter()
            .filter_map(struct_to_raw_cookie_chain))
    }

    fn str_to_json(raw_str: &str) -> Result<Vec<CookieStruct>, liberr::Err> {
        serde_json::from_str::<Vec<CookieStruct>>(raw_str).err_to_lib_err(line!())
    }

    fn struct_to_raw_cookie_chain<'a>(raw: CookieStruct) -> Option<RawCookie<'a>> {
        struct_to_raw_cookie(raw, false)
    }

    fn struct_to_raw_cookie<'a>(raw: CookieStruct, debug: bool) -> Option<RawCookie<'a>> {
        let time = match raw.expires {
            -1 => cookie::Expiration::Session,
            time => match OffsetDateTime::from_unix_timestamp(time) {
                Ok(datetime) => cookie::Expiration::DateTime(datetime),
                _ => cookie::Expiration::Session,
            },
        };
        if let cookie::Expiration::DateTime(dtime) = time {
            // TODO: Decide if an offset is needed, and if so, for how long, for now default to
            //  an hour.(dtime + Duration::hours(1))
            if dtime.checked_add(Duration::hours(1))? < OffsetDateTime::now_utc() {
                if debug {
                    println!("EXPIRED COOKIE: {raw:?} WITH DATE {dtime}");
                }
                return None;
            }
        }
        Some(
            RawCookie::build(raw.name, raw.value)
                .domain(raw.domain)
                .path(raw.path)
                .secure(raw.secure)
                .http_only(raw.httpOnly)
                .expires(time)
                .same_site(match raw.sameSite.as_deref() {
                    Some("Strict") => SameSite::Strict,
                    Some("Lax") => SameSite::Lax,
                    _ => SameSite::None,
                })
                .finish(),
        )
    }

    /// converts a formatted cookie struct to the intermediary custom struct so that it can be written
    ///  to a file
    #[inline]
    pub fn cookie_to_struct<'b>(cookie: &'b RawCookie<'b>) -> CookieStruct {
        CookieStruct {
            name: cookie.name().to_owned(),
            value: cookie.value().to_owned(),
            domain: cookie.domain().unwrap_or("").to_owned(),
            path: cookie.path().unwrap_or("").to_owned(),
            httpOnly: cookie.http_only().unwrap_or(false),
            secure: cookie.secure().unwrap_or(false),
            expires: match cookie.expires() {
                Some(exp) => match exp.datetime() {
                    Some(date) => date.unix_timestamp(),
                    None => -1,
                },
                None => -1,
            },
            sameSite: Some(
                match cookie.same_site() {
                    Some(site) => match site {
                        SameSite::Strict => "Strict",
                        SameSite::Lax => "Lax",
                        SameSite::None => "None",
                    },
                    None => "None",
                }
                .to_owned(),
            ),
        }
    }

    #[inline]
    pub fn export_cookie(path: &str, vec: &[CookieStruct]) -> Result<(), liberr::Err> {
        let mut buf = File::create(path)
            .map(BufWriter::new)
            .err_to_lib_err(line!())?;
        let vec = vec
            .iter()
            .map(serde_json::to_string_pretty)
            .collect::<Result<Vec<String>, _>>()
            .err_to_lib_err(line!())?;
        let write_string = String::from("[\n").add(vec.join(",").as_str()).add("\n]");
        write!(&mut buf, "{write_string}").err_to_lib_err(line!())?;
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::use_debug)]
    mod tests {
        use super::*;
        use conversions_rust_lib::ErrToLibErr;

        /// Checks that we can parse valid(?) json.
        #[test]
        fn test_cookie_parse() -> Result<(), Box<dyn std::error::Error>> {
            let raw_input: &str = r#"[
{
  "name": "messages",
  "value": "\"d5cbb8cbda62bbe615e0e5a023cc37f970fea1s7$[[\\\"__json_message\\\"\\0540\\05425\\054\\\"Successfully signed in as hello_from_jupiter.\\\"]]\"",
  "domain": ".leetcode.com",
  "path": "/",
  "httpOnly": true,
  "secure": true,
  "expires": -1,
  "sameSite": "Lax"
},{
  "name": "csrftoken",
  "value": "_INSERT_TOKEN_HERE",
  "domain": "leetcode.com",
  "path": "/",
  "httpOnly": false,
  "secure": true,
  "expires": -1,
  "sameSite": "Lax"
},{
  "name": "LEETCODE_SESSION",
  "value": "INSERT_SESSION_TOKEN_HERE",
  "domain": ".leetcode.com",
  "path": "/",
  "httpOnly": true,
  "secure": true,
  "expires": -1,
  "sameSite": "Lax"
}
]"#;
            let actual_struct = serde_json::from_str::<Vec<CookieStruct>>(raw_input)?;
            let actual = actual_struct
                .iter()
                .filter(|raw| {
                    match raw.expires {
                        -1 => true,
                        time => match OffsetDateTime::from_unix_timestamp(time) {
                            Ok(datetime) => {
                                // this is true when expiration time is 1 hour from now.
                                datetime > OffsetDateTime::now_utc() + Duration::hours(1)
                            }
                            // For now ignore if we cannot parse the timestamp.
                            _ => true,
                        },
                    }
                })
                .count();
            let vec_cookie = build_cookie(raw_input)?;
            assert_eq!(
                vec_cookie.len(),
                actual,
                "NOT ALL COOKIES WERE PARSED PARSED {} COOKIES, EXPECTED {} COOKIES",
                vec_cookie.len(),
                actual
            );
            let vec_struct = vec_cookie
                .iter()
                .map(cookie_to_struct)
                .collect::<Vec<CookieStruct>>();
            let raw_result = vec_struct
                .iter()
                .map(serde_json::to_string_pretty)
                .collect::<Result<Vec<String>, _>>()?;
            let result = String::from("[\n")
                .add(raw_result.join(",").as_str())
                .add("\n]");
            assert_eq!(result, raw_input);
            Ok(())
        }

        /// Checks that the functions properly check expiration.
        #[test]
        fn cookie_expiration_filter() -> Result<(), liberr::Err> {
            let raw_input = r#"[
            {
                "name": "messages",
                "value": "\"d5cbb8cbda62bbe615e0e5a023cc37f970fea1s7$[[\\\"__json_message\\\"\\0540\\05425\\054\\\"Successfully signed in as hello_from_jupiter.\\\"]]\"",
                "domain": ".leetcode.com",
                "path": "/",
                "expires": -1,
                "httpOnly": true,
                "secure": true,
                "sameSite": "Lax"
            },
            {
                "name": "_dd_s",
                "value": "rum=1&id=0035d843-4b8a-42d0-a686-b752aa462d24&created=1673484346515&expire=1673485276464",
                "domain": "leetcode.com",
                "path": "/",
                "expires": 1673485276,
                "httpOnly": false,
                "secure": false,
                "sameSite": "Strict"
            },
            {
                "name": "csrftoken",
                "value": "_INSERT_TOKEN_HERE",
                "domain": "leetcode.com",
                "path": "/",
                "expires": 1705027330,
                "httpOnly": false,
                "secure": true,
                "sameSite": "Lax"
            },
            {
                "name": "LEETCODE_SESSION",
                "value": "_INSERT_TOKEN_HERE",
                "domain": ".leetcode.com",
                "path": "/",
                "expires": -1,
                "httpOnly": true,
                "secure": true,
                "sameSite": "Lax"
            }
        ]"#;
            let expected = 3;
            let vec_cookie = build_cookie(raw_input).err_to_lib_err(line!())?;
            let actual = vec_cookie.len();
            assert_eq!(
                actual, expected,
                "COOKIES PARSED {}, EXPECTED {}",
                actual, expected
            );
            Ok(())
        }
        /// Checks that cookies can be parsed from a properly formatted(?) json file.
        #[test]
        fn from_file() -> Result<(), Box<dyn std::error::Error>> {
            // let file = File::open("data/cookie_1_28_2023.json")?;
            // let rbuf = BufReader::new(file);
            let string = std::fs::read_to_string("data/cookie_1_28_2023.json")?;
            let cookies = build_cookie(string.as_str())?;
            for cookie in cookies {
                println!("{cookie:?}");
            }
            Ok(())
        }
    }
}

pub mod scrapper_cookie_store {
    use crate::scrapper_cookie;
    use reqwest_cookie_store::{CookieStore as RCS_CookieStore, CookieStoreMutex};
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::sync::Arc;

    /// Enum used to handle multiple json scenarios.
    ///
    /// `InitialCookies::CookieStoreJson` : formatted the way `cookie_store` already can parse. Wraps
    ///     around `CookieStore::load_json`.
    ///
    ///
    /// `InitialCookies::RawArrayJson` : simple format where the json file consists of a top-level
    ///     array of objects. Uses a built-in parser to insert valid cookies into the store.
    ///
    ///
    /// `InitialCookies::None` : Simply Initializes a new `CookieStore`.
    pub enum InitialCookies {
        CookieStoreJson(BufReader<File>),
        RawArrayJson(BufReader<File>),
        None,
    }
    /// This function initializes a cookie store
    ///
    /// Using the data inside the parameter data, creates a `CookieStore` wraps around a Mutex, and
    /// wraps that around a `Arc`.
    pub fn init_cookie_store(data: InitialCookies) -> Arc<CookieStoreMutex> {
        let cookie_store = match data {
            InitialCookies::CookieStoreJson(json_file) => RCS_CookieStore::load_json(json_file)
                .unwrap_or_else(|e| {
                    println!("ERROR: {e}, defaulting to empty cookie_store");
                    reqwest_cookie_store::CookieStore::default()
                }),
            InitialCookies::RawArrayJson(mut json_file) => {
                let mut store = RCS_CookieStore::default();
                let mut raw_data = String::new();
                // Ignore the read to str
                let _size = json_file.read_to_string(&mut raw_data);
                let cookies = scrapper_cookie::build_cookies_url(&raw_data);
                for (cookie, url) in cookies {
                    let _cookie_result = store.insert_raw(&cookie, &url);
                }
                store
            }
            InitialCookies::None => RCS_CookieStore::default(),
        };
        let cookie_store = CookieStoreMutex::new(cookie_store);
        Arc::new(cookie_store)
    }
    #[cfg(test)]
    mod tests {
        use crate::scrapper_cookie_store::{init_cookie_store, InitialCookies};
        use conversions_rust_lib::ErrToLibErr;
        use reqwest_cookie_store::CookieStoreMutex;
        use std::fs::File;
        use std::io::BufReader;
        use std::sync::Arc;

        fn count_cookies(cookie_store: Arc<CookieStoreMutex>) -> Result<i32, liberr::Err> {
            let mut counter = 0;
            let store = cookie_store.lock().err_to_lib_err(line!())?;
            for cookie in store.iter_any() {
                counter += 1;
                println!("{cookie:?}");
            }
            Ok(counter)
        }

        #[test]
        fn it_works() -> Result<(), Box<dyn std::error::Error>> {
            let raw_array_json = File::open("./data/cookie_1_28_2023.json").map(BufReader::new)?;
            let cookie_type = InitialCookies::RawArrayJson(raw_array_json);
            let cookie_store = init_cookie_store(cookie_type);
            let counter = count_cookies(Arc::clone(&cookie_store))?;
            assert_ne!(counter, 0);
            let cookie_store = File::open("./data/cookie_store.json")
                .map(BufReader::new)
                .map(InitialCookies::CookieStoreJson)?;
            let cookie_store = init_cookie_store(cookie_store);
            let counter = count_cookies(Arc::clone(&cookie_store))?;
            assert_ne!(counter, 0);
            Ok(())
        }
    }
}

pub mod headers {
    use conversions_rust_lib::ErrToLibErr;
    use core::str::FromStr;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    use std::fs::File;
    use std::io;
    use std::io::{BufRead, BufReader};

    pub trait IterStr {
        fn from_str_iter(
            values: impl Iterator<Item = (String, String)>,
        ) -> Result<Self, liberr::Err>
        where
            Self: Sized;
    }
    impl IterStr for HeaderMap {
        fn from_str_iter(
            values: impl Iterator<Item = (String, String)>,
        ) -> Result<Self, liberr::Err>
        where
            Self: Sized,
        {
            let mut ret = HeaderMap::new();
            for (key, val) in values {
                let key = HeaderName::from_str(key.as_str()).err_to_lib_err(line!())?;
                let val = HeaderValue::from_str(val.as_str()).err_to_lib_err(line!())?;
                ret.insert(key, val);
            }
            Ok(ret)
        }
    }
    pub fn get_headers(
        path: &str,
    ) -> io::Result<impl Iterator<Item = Result<(String, String), io::Error>>> {
        let iter = File::open(path).map(BufReader::new)?.lines().map(|line| {
            line.map(|line| {
                let mut line = line.split(": ").map(String::from);
                (line.next().unwrap(), line.next().unwrap())
            })
        });
        Ok(iter)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn test_get_headers() -> Result<(), Box<dyn std::error::Error>> {
            let _headers = get_headers("./data/headers.txt")?;
            Ok(())
        }
        #[test]
        fn test_headers_provider() -> Result<(), Box<dyn std::error::Error>> {
            let map = HeaderMap::from_str_iter((get_headers("./data/headers.txt")?).flatten())?;
            for (key, value) in map {
                assert!(key.is_some());
                if let Some(key) = key {
                    println!("KEY: {key:?} VAL: {value:?}");
                }
            }
            Ok(())
        }
    }
}
