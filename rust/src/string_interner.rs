use std::collections::HashMap;

macro_rules! intern_method {
    ($method_name:ident, $field:ident, $type:ident, $type_name:expr) => {
        pub fn $method_name(&mut self, s: &str) -> $type {
            if let Some(&id) = self.$field.get(s) {
                return id;
            }

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
pub struct KeyId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentHash(pub usize);

/// An output name like "out", "dev", "lib".
/// Interned in its own namespace so collisions with drv paths are impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutputName(pub usize);

pub struct StringInterner {
    udrv_to_id: HashMap<String, UDrv>,
    rdrv_to_id: HashMap<String, RDrv>,
    key_to_id: HashMap<String, KeyId>,
    content_hash_to_id: HashMap<String, ContentHash>,
    output_name_to_id: HashMap<String, OutputName>,

    // Keeps type-confusion detection across all interned namespaces except OutputName,
    // because output names like "out" naturally re-occur and shouldn't be considered
    // confusable with anything else.
    all_strings: HashMap<String, &'static str>,

    id_to_string: Vec<String>,
}

impl StringInterner {
    pub fn new() -> Self {
        StringInterner {
            udrv_to_id: HashMap::new(),
            rdrv_to_id: HashMap::new(),
            key_to_id: HashMap::new(),
            content_hash_to_id: HashMap::new(),
            output_name_to_id: HashMap::new(),
            all_strings: HashMap::new(),
            id_to_string: Vec::new(),
        }
    }

    intern_method!(udrv, udrv_to_id, UDrv, "UDrv");
    intern_method!(rdrv, rdrv_to_id, RDrv, "RDrv");
    intern_method!(key, key_to_id, KeyId, "KeyId");
    intern_method!(content_hash, content_hash_to_id, ContentHash, "ContentHash");

    /// Output names are interned in their own namespace; "out" can be reused
    /// across every derivation without conflicting with anything else.
    pub fn output_name(&mut self, s: &str) -> OutputName {
        if let Some(&id) = self.output_name_to_id.get(s) {
            return id;
        }
        let id = self.id_to_string.len();
        self.id_to_string.push(s.to_string());
        let typed = OutputName(id);
        self.output_name_to_id.insert(s.to_string(), typed);
        typed
    }

    pub fn get_string(&self, id: usize) -> Option<&str> {
        self.id_to_string.get(id).map(|s| s.as_str())
    }

    pub fn udrv_str(&self, id: UDrv) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn rdrv_str(&self, id: RDrv) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn key_str(&self, id: KeyId) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn content_hash_str(&self, id: ContentHash) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn output_name_str(&self, id: OutputName) -> Option<&str> {
        self.get_string(id.0)
    }
}
