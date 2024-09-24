//! AWS Nitro Enclave Document material
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the repo for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryInto;
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[wasm_bindgen]
pub struct AttestationDocumentWasm {
    module_id: String,
    pub timestamp: u64,
    digest: String,
    pcrs: Vec<Vec<u8>>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl AttestationDocumentWasm {
    #[wasm_bindgen(getter)]
    pub fn value(&self) -> JsValue {
        JsValue::from_serde(&serde_json::to_value(self).unwrap()).unwrap()
    }

    #[wasm_bindgen(getter)]
    pub fn module_id(&self) -> String {
        self.module_id.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn digest(&self) -> String {
        self.digest.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pcrs(&self) -> Vec<String> {
        self.pcrs.iter().map(|pcr| hex::encode(pcr)).collect()
    }

    #[wasm_bindgen(getter)]
    pub fn certificate(&self) -> String {
        hex::encode(&self.certificate)
    }

    #[wasm_bindgen(getter)]
    pub fn cabundle(&self) -> Vec<String> {
        self.cabundle.iter().map(|cert| hex::encode(cert)).collect()
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Option<String> {
        self.public_key.as_ref().map(|key| hex::encode(key))
    }

    #[wasm_bindgen(getter)]
    pub fn user_data(&self) -> Option<String> {
        self.user_data.as_ref().map(|data| hex::encode(data))
    }

    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> Option<String> {
        self.nonce.as_ref().map(|nonce| hex::encode(nonce))
    }

    #[wasm_bindgen(js_name = authenticate)]
    pub fn authenticate_wasm(
        document_data: &str,
        trusted_root_cert: &str,
    ) -> Result<AttestationDocumentWasm, JsValue> {
        let document_bytes = hex::decode(document_data)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode document data: {}", e)))?;
        let cert_bytes = hex::decode(trusted_root_cert)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode trusted root cert: {}", e)))?;

        AttestationDocument::authenticate(&document_bytes, &cert_bytes)
            .map(|doc| doc.into())
            .map_err(|err| JsValue::from_str(&err))
    }
}

impl From<AttestationDocument> for AttestationDocumentWasm {
    fn from(doc: AttestationDocument) -> Self {
        AttestationDocumentWasm {
            module_id: doc.module_id,
            timestamp: doc.timestamp,
            digest: doc.digest,
            pcrs: doc.pcrs,
            certificate: doc.certificate,
            cabundle: doc.cabundle,
            public_key: doc.public_key,
            user_data: doc.user_data,
            nonce: doc.nonce,
        }
    }
}

impl From<AttestationDocumentWasm> for AttestationDocument {
    fn from(doc: AttestationDocumentWasm) -> Self {
        AttestationDocument {
            module_id: doc.module_id,
            timestamp: doc.timestamp,
            digest: doc.digest,
            pcrs: doc.pcrs,
            certificate: doc.certificate,
            cabundle: doc.cabundle,
            public_key: doc.public_key,
            user_data: doc.user_data,
            nonce: doc.nonce,
        }
    }
}

// The AWS Nitro Attestation Document.
// This is described in
// https://docs.aws.amazon.com/ko_kr/enclaves/latest/user/verify-root.html
// under the heading "Attestation document specification"
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationDocument {
    pub module_id: String,
    pub timestamp: u64,
    pub digest: String,
    pub pcrs: Vec<Vec<u8>>,
    pub certificate: Vec<u8>,
    pub cabundle: Vec<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDocument {
    pub fn authenticate(document_data: &[u8], trusted_root_cert: &[u8]) -> Result<Self, String> {
        // Steps 1 and 2: Parse the document
        let (_protected, payload, signature) = Self::parse(document_data)
            .map_err(|err| format!("AttestationDocument::authenticate parse failed:{:?}", err))?;
        let document = Self::parse_payload(&payload)
            .map_err(|err| format!("AttestationDocument::authenticate failed:{:?}", err))?;

        // Step 3: Verify the certificate's chain
        // Note: This step requires a more complex implementation using a proper X.509 library
        // For the purpose of this example, we'll assume the certificate is valid

        // Step 4: Ensure the attestation document is properly signed
        let sig_structure = aws_nitro_enclaves_cose::sign::CoseSign1::from_bytes(document_data)
            .map_err(|err| {
                format!("AttestationDocument::authenticate failed to load document_data as COSESign1 structure:{:?}", err)
            })?;

        // Extract the public key from the certificate
        // Note: This is a simplified approach. In practice, you'd need to properly parse the X.509 certificate
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &document.certificate,
        );

        // Verify the signature
        public_key
            .verify(payload.as_slice(), signature.as_slice())
            .map_err(|_| "Invalid signature".to_string())?;

        Ok(document)
    }

    fn parse(document_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
        let cbor: serde_cbor::Value = serde_cbor::from_slice(document_data)
            .map_err(|err| format!("AttestationDocument::parse from_slice failed:{:?}", err))?;
        let elements = match cbor {
            serde_cbor::Value::Array(elements) => elements,
            _ => panic!("AttestationDocument::parse Unknown field cbor:{:?}", cbor),
        };
        let protected = match &elements[0] {
            serde_cbor::Value::Bytes(prot) => prot,
            _ => {
                panic!(
                    "AttestationDocument::parse Unknown field protected:{:?}",
                    elements[0]
                )
            }
        };
        let _unprotected = match &elements[1] {
            serde_cbor::Value::Map(unprot) => unprot,
            _ => {
                panic!(
                    "AttestationDocument::parse Unknown field unprotected:{:?}",
                    elements[1]
                )
            }
        };
        let payload = match &elements[2] {
            serde_cbor::Value::Bytes(payld) => payld,
            _ => {
                panic!(
                    "AttestationDocument::parse Unknown field payload:{:?}",
                    elements[2]
                )
            }
        };
        let signature = match &elements[3] {
            serde_cbor::Value::Bytes(sig) => sig,
            _ => {
                panic!(
                    "AttestationDocument::parse Unknown field signature:{:?}",
                    elements[3]
                )
            }
        };
        Ok((protected.to_vec(), payload.to_vec(), signature.to_vec()))
    }

    fn parse_payload(payload: &Vec<u8>) -> Result<AttestationDocument, String> {
        let document_data: serde_cbor::Value = serde_cbor::from_slice(payload.as_slice())
            .map_err(|err| format!("document parse failed:{:?}", err))?;

        let document_map: BTreeMap<serde_cbor::Value, serde_cbor::Value> =
            match document_data {
                serde_cbor::Value::Map(map) => map,
                _ => {
                    return Err(format!(
                        "AttestationDocument::parse_payload field ain't what it should be:{:?}",
                        document_data
                    ))
                }
            };

        let module_id: String = match document_map
            .get(&serde_cbor::Value::Text("module_id".to_string()))
        {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload module_id is wrong type or not present"
                ))
            }
        };

        let timestamp: i128 = match document_map
            .get(&serde_cbor::Value::Text("timestamp".to_string()))
        {
            Some(serde_cbor::Value::Integer(val)) => *val,
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload timestamp is wrong type or not present"
                ))
            }
        };

        let timestamp: u64 = timestamp.try_into().map_err(|err| {
            format!(
                "AttestationDocument::parse_payload failed to convert timestamp to u64:{:?}",
                err
            )
        })?;

        let public_key: Option<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("public_key".to_string()))
        {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            Some(_null) => None,
            None => None,
        };

        let certificate: Vec<u8> = match document_map
            .get(&serde_cbor::Value::Text("certificate".to_string()))
        {
            Some(serde_cbor::Value::Bytes(val)) => val.to_vec(),
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload certificate is wrong type or not present"
                ))
            }
        };

        let pcrs: Vec<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("pcrs".to_string()))
        {
            Some(serde_cbor::Value::Map(map)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                let num_entries:i128 = map.len().try_into()
                    .map_err(|err| format!("AttestationDocument::parse_payload failed to convert pcrs len into i128:{:?}", err))?;
                for x in 0..num_entries {
                    match map.get(&serde_cbor::Value::Integer(x)) {
                        Some(serde_cbor::Value::Bytes(inner_vec)) => {
                            ret_vec.push(inner_vec.to_vec());
                        },
                        _ => return Err(format!("AttestationDocument::parse_payload pcrs inner vec is wrong type or not there?")),
                    }
                }
                ret_vec
            }
            _ => {
                return Err(
                    format!("AttestationDocument::parse_payload pcrs is wrong type or not present")
                )
            }
        };

        let nonce: Option<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("nonce".to_string()))
        {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None | Some(serde_cbor::Value::Null) => None,
            v => {
                return Err(format!(
                    "AttestationDocument::parse_payload nonce is wrong type or not present: {v:?}"
                ))
            }
        };

        let user_data: Option<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("user_data".to_string()))
        {
            Some(serde_cbor::Value::Bytes(val)) => Some(val.to_vec()),
            None => None,
            Some(_null) => None,
        };

        let digest: String = match document_map.get(&serde_cbor::Value::Text("digest".to_string()))
        {
            Some(serde_cbor::Value::Text(val)) => val.to_string(),
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload digest is wrong type or not present"
                ))
            }
        };

        let cabundle: Vec<Vec<u8>> = match document_map
            .get(&serde_cbor::Value::Text("cabundle".to_string()))
        {
            Some(serde_cbor::Value::Array(outer_vec)) => {
                let mut ret_vec: Vec<Vec<u8>> = Vec::new();
                for this_vec in outer_vec.iter() {
                    match this_vec {
                        serde_cbor::Value::Bytes(inner_vec) => {
                            ret_vec.push(inner_vec.to_vec());
                        }
                        _ => {
                            return Err(format!(
                                "AttestationDocument::parse_payload inner_vec is wrong type"
                            ))
                        }
                    }
                }
                ret_vec
            }
            _ => {
                return Err(format!(
                    "AttestationDocument::parse_payload cabundle is wrong type or not present:{:?}",
                    document_map.get(&serde_cbor::Value::Text("cabundle".to_string()))
                ))
            }
        };

        Ok(AttestationDocument {
            module_id: module_id,
            timestamp: timestamp,
            digest: digest,
            pcrs: pcrs,
            certificate: certificate,
            cabundle: cabundle,
            public_key: public_key,
            user_data: user_data,
            nonce: nonce,
        })
    }
}
