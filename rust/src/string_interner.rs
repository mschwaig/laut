use std::collections::HashMap;

// Macro to generate intern methods
macro_rules! intern_method {
    ($method_name:ident, $field:ident, $type:ident, $type_name:expr) => {
        pub fn $method_name(&mut self, s: &str) -> $type {
            if let Some(&id) = self.$field.get(s) {
                return id;
            }

            // Check for type confusion
            if let Some(&existing_type) = self.all_strings.get(s) {
                panic!("Type confusion: string '{}' was already interned as type '{}', cannot intern as type '{}'",
                       s, existing_type, $type_name);
            }

            let id = self.id_to_string.len();
            let string = s.to_string();
            self.id_to_string.push(string.clone());
            let typed_id = $type(id);
            self.$field.insert(string.clone(), typed_id);
            self.all_strings.insert(string, $type_name);
            typed_id
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UDrv(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RDrv(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TrustModel(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UDrvOutput(pub usize);

pub struct StringInterner {
    // Separate hashmaps for each type
    udrv_to_id: HashMap<String, UDrv>,
    rdrv_to_id: HashMap<String, RDrv>,
    trust_model_to_id: HashMap<String, TrustModel>,
    content_hash_to_id: HashMap<String, ContentHash>,
    udrv_output_to_id: HashMap<String, UDrvOutput>,

    // Common hashmap to detect type confusion
    all_strings: HashMap<String, &'static str>, // maps string -> type name

    // Reverse mappings for string retrieval
    id_to_string: Vec<String>,
}

impl StringInterner {
    pub fn new() -> Self {
        StringInterner {
            udrv_to_id: HashMap::new(),
            rdrv_to_id: HashMap::new(),
            trust_model_to_id: HashMap::new(),
            content_hash_to_id: HashMap::new(),
            udrv_output_to_id: HashMap::new(),
            all_strings: HashMap::new(),
            id_to_string: Vec::new(),
        }
    }

    intern_method!(udrv, udrv_to_id, UDrv, "UDrv");
    intern_method!(rdrv, rdrv_to_id, RDrv, "RDrv");
    intern_method!(trust_model, trust_model_to_id, TrustModel, "TrustModel");
    intern_method!(content_hash, content_hash_to_id, ContentHash, "ContentHash");
    intern_method!(udrv_output, udrv_output_to_id, UDrvOutput, "UDrvOutput");

    pub fn get_string(&self, id: usize) -> Option<&str> {
        self.id_to_string.get(id).map(|s| s.as_str())
    }

    pub fn udrv_str(&self, id: UDrv) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn rdrv_str(&self, id: RDrv) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn trust_model_str(&self, id: TrustModel) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn content_hash_str(&self, id: ContentHash) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn udrv_output_str(&self, id: UDrvOutput) -> Option<&str> {
        self.get_string(id.0)
    }

    // Methods to get readonly views of all values of each type
    pub fn all_udrvs(&self) -> impl Iterator<Item = &UDrv> {
        self.udrv_to_id.values()
    }

    pub fn all_rdrvs(&self) -> impl Iterator<Item = &RDrv> {
        self.rdrv_to_id.values()
    }

    pub fn all_trust_models(&self) -> impl Iterator<Item = &TrustModel> {
        self.trust_model_to_id.values()
    }

    pub fn all_content_hashes(&self) -> impl Iterator<Item = &ContentHash> {
        self.content_hash_to_id.values()
    }

    pub fn all_udrv_outputs(&self) -> impl Iterator<Item = &UDrvOutput> {
        self.udrv_output_to_id.values()
    }

    // Efficient count methods
    pub fn udrvs_count(&self) -> usize {
        self.udrv_to_id.len()
    }

    pub fn rdrvs_count(&self) -> usize {
        self.rdrv_to_id.len()
    }

    pub fn trust_models_count(&self) -> usize {
        self.trust_model_to_id.len()
    }

    pub fn content_hashes_count(&self) -> usize {
        self.content_hash_to_id.len()
    }

    pub fn udrv_outputs_count(&self) -> usize {
        self.udrv_output_to_id.len()
    }
}