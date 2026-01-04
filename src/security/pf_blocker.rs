use std::net::IpAddr;
use std::process::Command;
use tokio::sync::mpsc;

pub struct PfBlocker {
    table_name: String,
    tx: mpsc::UnboundedSender<IpAddr>,
}

impl PfBlocker {
    pub fn new(table_name: String) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<IpAddr>();

        let table = table_name.clone();

        // Spawn background task to process blocking requests
        tokio::spawn(async move {
            while let Some(ip) = rx.recv().await {
                if let Err(e) = Self::block_ip(&table, ip) {
                    eprintln!("❌ Failed to block IP {}: {}", ip, e);
                } else {
                    println!("🚫 Blocked IP {} in PF table '{}'", ip, table);
                }
            }
        });

        Self { table_name, tx }
    }

    /// Queue an IP to be blocked
    pub fn block(&self, ip: IpAddr) {
        if let Err(e) = self.tx.send(ip) {
            eprintln!("Failed to queue IP for blocking: {}", e);
        }
    }

    /// Actually execute the pfctl command to add IP to table
    fn block_ip(table: &str, ip: IpAddr) -> Result<(), String> {
        // Execute: pfctl -t <table_name> -T add <ip>
        let output = Command::new("pfctl")
            .arg("-t")
            .arg(table)
            .arg("-T")
            .arg("add")
            .arg(ip.to_string())
            .output()
            .map_err(|e| format!("Failed to execute pfctl: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("pfctl error: {}", stderr));
        }

        Ok(())
    }

    /// Check current table size
    pub fn get_table_size(&self) -> Result<usize, String> {
        // Execute: pfctl -t <table_name> -T show | wc -l
        let output = Command::new("pfctl")
            .arg("-t")
            .arg(&self.table_name)
            .arg("-T")
            .arg("show")
            .output()
            .map_err(|e| format!("Failed to execute pfctl: {}", e))?;

        if !output.status.success() {
            return Err("pfctl show failed".to_string());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.lines().count())
    }

    /// Flush all IPs from the table
    pub fn flush_table(&self) -> Result<(), String> {
        let output = Command::new("pfctl")
            .arg("-t")
            .arg(&self.table_name)
            .arg("-T")
            .arg("flush")
            .output()
            .map_err(|e| format!("Failed to execute pfctl: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("pfctl flush error: {}", stderr));
        }

        println!("🧹 Flushed PF table '{}'", self.table_name);
        Ok(())
    }
}
