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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "Type confusion: string 'test_string' was already interned as type 'UDrv', cannot intern as type 'RDrv'")]
    fn test_type_confusion_detection() {
        let mut interner = StringInterner::new();
        let _udrv_id = interner.udrv("test_string");
        let _rdrv_id = interner.rdrv("test_string");
    }

    #[test]
    fn test_same_type_multiple_times() {
        let mut interner = StringInterner::new();
        let udrv_id1 = interner.udrv("test_string");
        let udrv_id2 = interner.udrv("test_string");
        assert_eq!(udrv_id1, udrv_id2);
    }

    #[test]
    fn test_different_strings_different_types() {
        let mut interner = StringInterner::new();
        let udrv_id = interner.udrv("udrv_string");
        let rdrv_id = interner.rdrv("rdrv_string");
        let key_id = interner.key("key_string");

        assert_eq!(udrv_id.0, 0);
        assert_eq!(rdrv_id.0, 1);
        assert_eq!(key_id.0, 2);
    }

    #[test]
    fn test_output_names_reusable() {
        let mut interner = StringInterner::new();
        // Output names live in their own namespace and shouldn't trigger
        // type-confusion against other namespaces using common short strings.
        let _udrv = interner.udrv("/nix/store/abc-foo.drv");
        let out_a = interner.output_name("out");
        let out_b = interner.output_name("out");
        assert_eq!(out_a, out_b);
    }
}
