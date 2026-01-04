use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Hit {
    pub count: u32,
    pub first_seen: Instant,
    pub last_seen: Instant,
}

pub struct RateLimiter {
    // Track 404 hits per IP
    hits: Arc<RwLock<HashMap<IpAddr, Hit>>>,
    // Configuration
    threshold: u32,           // Number of 404s before action
    window_secs: u64,         // Time window to count hits
    cleanup_interval: Duration,
}


impl RateLimiter {
    pub fn new(threshold: u32, window_secs: u64) -> Self {
        Self {
            hits: Arc::new(RwLock::new(HashMap::new())),
            threshold,
            window_secs,
            cleanup_interval: Duration::from_secs(60), // Clean up old entries every minute
        }
    }

    /// Record a 404 hit from an IP address
    /// Returns true if the IP has exceeded the threshold
    pub fn record_404(&self, ip: IpAddr) -> bool {
        let mut hits = self.hits.write().unwrap();
        let now = Instant::now();

        let hit = hits.entry(ip).or_insert(Hit {
            count: 0,
            first_seen: now,
            last_seen: now,
        });

        // Check if we're still within the time window
        let elapsed = now.duration_since(hit.first_seen);
        if elapsed > Duration::from_secs(self.window_secs) {
            // Reset the counter, start new window
            hit.count = 1;
            hit.first_seen = now;
            hit.last_seen = now;
            false
        } else {
            // Increment counter
            hit.count += 1;
            hit.last_seen = now;

            // Check if threshold exceeded
            if hit.count >= self.threshold {
                println!(
                    "⚠️  IP {} exceeded 404 threshold: {} hits in {} seconds",
                    ip, hit.count, elapsed.as_secs()
                );
                true
            } else {
                false
            }
        }
    }

    /// Get current hit count for an IP
    pub fn get_hit_count(&self, ip: IpAddr) -> Option<u32> {
        let hits = self.hits.read().unwrap();
        hits.get(&ip).map(|h| h.count)
    }

    /// Clean up old entries that are outside the time window
    pub fn cleanup(&self) {
        let mut hits = self.hits.write().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);

        hits.retain(|ip, hit| {
            let elapsed = now.duration_since(hit.last_seen);
            if elapsed > window {
                println!("🧹 Cleaning up old entry for {}", ip);
                false // Remove this entry
            } else {
                true // Keep this entry
            }
        });
    }

    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.cleanup_interval);
            loop {
                interval.tick().await;
                self.cleanup();
            }
        });
    }

    /// Get statistics
    pub fn get_stats(&self) -> (usize, Vec<(IpAddr, u32)>) {
        let hits = self.hits.read().unwrap();
        let total = hits.len();
        let mut top: Vec<_> = hits
            .iter()
            .map(|(ip, hit)| (*ip, hit.count))
            .collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10); // Top 10
        (total, top)
    }
}
