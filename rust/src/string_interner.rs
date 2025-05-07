use std::collections::HashMap;

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

    pub fn get_string(&self, id: usize) -> Option<&str> {
        self.id_to_string.get(id).map(|s| s.as_str())
    }
}