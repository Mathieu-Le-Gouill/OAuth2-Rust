use super::Provider;
use std::collections::HashMap;
use std::sync::Arc;

pub struct Registry {
    providers: HashMap<String, Arc<Provider>>,
}


impl Registry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new()
        }
    }


    pub fn register(&mut self, provider: Provider) {
        self.providers.insert(provider.identity.name.to_string(), Arc::new(provider));
    }


    pub fn get(&self, provider_name: &str) -> Option<&Arc<Provider>> {
        self.providers.get(provider_name)
    }
}