use crate::config::{BackendConfig, ProxyRoute, ProxySettings};

#[derive(Clone, Debug)]
pub struct Backend {
    pub name: String,
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub enabled: bool,
}

impl Backend {
    pub fn from_config(config: BackendConfig) -> Self {
        Self {
            name: config.name,
            url: config.url,
            weight: config.weight,
            healthy: true,
            enabled: config.enabled,
        }
    }
}

pub struct ProxyConfig {
    pub backends: Vec<Backend>,
    pub routes: Vec<ProxyRoute>,
    pub current_backend: std::sync::atomic::AtomicUsize,
}

impl ProxyConfig {
    pub fn new(settings: ProxySettings) -> Self {
        Self {
            backends: settings.backends.into_iter()
                .map(Backend::from_config)
                .collect(),
            routes: settings.routes,
            current_backend: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn get_backend_by_name(&self, name: &str) -> Option<&Backend> {
        self.backends.iter()
            .find(|b| b.name == name && b.enabled && b.healthy)
    }

    pub fn get_next_backend(&self) -> Option<&Backend> {
        if self.backends.is_empty() {
            return None;
        }

        let start = self.current_backend.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        
        for i in 0..self.backends.len() {
            let idx = (start + i) % self.backends.len();
            let backend = &self.backends[idx];
            if backend.healthy && backend.enabled {
                return Some(backend);
            }
        }
        None
    }

    pub fn find_route(&self, path: &str) -> Option<&ProxyRoute> {
        self.routes.iter()
            .find(|route| path.starts_with(&route.path_prefix))
    }
}
