pub trait Database {
    // TODO: Error type
    fn store(&mut self, key: &[u64], value: &[u64]) -> Result<(), String>;
    fn load(&self, key: &[u64]) -> Result<(), String>;
}
