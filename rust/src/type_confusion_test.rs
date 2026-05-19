#[cfg(test)]
mod tests {
    use crate::string_interner::StringInterner;

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
