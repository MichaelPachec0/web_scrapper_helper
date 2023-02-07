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

use serde::{Deserialize, Serialize};

#[allow(non_snake_case)]
#[derive(Deserialize, Serialize, Debug)]
#[non_exhaustive]
pub struct CookieStruct {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    // The fields bellow are likely optional, that is to say,
    // for the case of expires, might have a -1, which when converting from
    // unix timestamp, will result in an error,
    pub httpOnly: bool,
    pub secure: bool,
    pub expires: i64,
    pub sameSite: Option<String>,
}
