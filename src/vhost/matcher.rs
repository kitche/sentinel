#[derive(Debug, Clone)]
pub struct VirtualHost {
    pub server_names: Vec<String>,
    pub document_root: Option<String>,
    pub proxy_backend: Option<String>,
    pub proxy_routes: Vec<crate::config::ProxyRoute>,
    pub php_config: Option<crate::config::PhpConfig>,
}

impl VirtualHost {
    pub fn from_config(config: crate::config::VirtualHost) -> Self {
        let mut server_names = config.server_name.clone();
        server_names.extend(config.aliases.clone());

        Self {
            server_names,
            document_root: config.document_root,
            proxy_backend: config.proxy.as_ref().map(|p| p.backend.clone()),
            proxy_routes: config.proxy
                .map(|p| p.routes)
                .unwrap_or_default(),
            php_config: config.php,
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        // Remove port from host if present
        let host_without_port = host.split(':').next().unwrap_or(host);
        
        for server_name in &self.server_names {
            if Self::matches_pattern(server_name, host_without_port) {
                return true;
            }
        }
        false
    }

    fn matches_pattern(pattern: &str, host: &str) -> bool {
        // Support wildcards
        if pattern.starts_with('*') {
            // *.example.com matches www.example.com, api.example.com
            let suffix = &pattern[1..]; // Remove *
            host.ends_with(suffix)
        } else if pattern.starts_with('.') {
            // .example.com matches example.com, www.example.com
            host == &pattern[1..] || host.ends_with(pattern)
        } else {
            // Exact match
            pattern == host
        }
    }
}

pub struct VirtualHostMatcher {
    vhosts: Vec<VirtualHost>,
}

impl VirtualHostMatcher {
    pub fn new(vhosts: Vec<crate::config::VirtualHost>) -> Self {
        let vhosts: Vec<VirtualHost> = vhosts
            .into_iter()
            .filter(|v| v.enabled)
            .map(VirtualHost::from_config)
            .collect();

        Self { vhosts }
    }

    pub fn find_vhost(&self, host: Option<&str>) -> Option<&VirtualHost> {
        let host = host?;

        // Try to find matching vhost
        for vhost in &self.vhosts {
            if vhost.matches(host) {
                return Some(vhost);
            }
        }

        None
    }
}
