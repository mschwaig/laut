use std::collections::HashMap;

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
    string_to_id: HashMap<String, usize>,
    id_to_string: Vec<String>,
}

impl StringInterner {
    pub fn new() -> Self {
        StringInterner {
            string_to_id: HashMap::new(),
            id_to_string: Vec::new(),
        }
    }

    pub fn intern(&mut self, s: &str) -> usize {
        if let Some(&id) = self.string_to_id.get(s) {
            return id;
        }

        let id = self.id_to_string.len();
        let string = s.to_string();

        self.string_to_id.insert(string.clone(), id);
        self.id_to_string.push(string);

        id
    }

    pub fn udrv(&mut self, s: &str) -> UDrv {
        UDrv(self.intern(s))
    }

    pub fn rdrv(&mut self, s: &str) -> RDrv {
        RDrv(self.intern(s))
    }

    pub fn trust_model(&mut self, s: &str) -> TrustModel {
        TrustModel(self.intern(s))
    }

    pub fn content_hash(&mut self, s: &str) -> ContentHash {
        ContentHash(self.intern(s))
    }

    pub fn udrv_output(&mut self, s: &str) -> UDrvOutput {
        UDrvOutput(self.intern(s))
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

    pub fn trust_model_str(&self, id: TrustModel) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn content_hash_str(&self, id: ContentHash) -> Option<&str> {
        self.get_string(id.0)
    }

    pub fn udrv_output_str(&self, id: UDrvOutput) -> Option<&str> {
        self.get_string(id.0)
    }
}