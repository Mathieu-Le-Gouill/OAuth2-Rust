use super::Provider;
use std::collections::HashMap;
use std::sync::Arc;


/// In-memory registry that stores OAuth providers indexed by name for fast lookup and reuse
pub struct Registry {
    providers: HashMap<String, Arc<Provider>>,
}


impl Registry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new()
        }
    }


    /// Registers a provider into the registry by wrapping it in an `Arc` for shared ownership
    pub fn register(&mut self, provider: Provider) {
        self.providers.insert(provider.identity.name.to_string(), Arc::new(provider));
    }

    /// Retrieves a provider by name, returning a shared reference-counted handle if it exists
    pub fn get(&self, provider_name: &str) -> Option<&Arc<Provider>> {
        self.providers.get(provider_name)
    }
}