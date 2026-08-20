//! Live system status.

use std::path::PathBuf;

use serde::Serialize;
use sysinfo::{Disks, System};

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub host: String,
    pub os: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub cpu_count: usize,
    pub cpu_usage: f32,
    pub load: [f64; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub volumes: Vec<Volume>,
    pub top_processes: Vec<Process>,
    pub health: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Volume {
    pub mount: PathBuf,
    pub total: u64,
    pub available: u64,
}

impl Volume {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.available)
    }
    pub fn used_pct(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.used() as f64 / self.total as f64 * 100.0
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cpu: f32,
    pub memory: u64,
}

/// A judgement, not just a number. A dashboard that only shows values makes
/// the reader do the diagnosis.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: Level,
    pub subject: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Ok,
    Warn,
    Critical,
}

pub fn collect() -> Status {
    let mut sys = System::new_all();
    sys.refresh_all();
    // CPU percentages need two samples separated by at least the minimum
    // refresh interval; a single snapshot reports zero for everything.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_cpu_usage();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let volumes: Vec<Volume> = Disks::new_with_refreshed_list()
        .list()
        .iter()
        .map(|d| Volume {
            mount: d.mount_point().to_path_buf(),
            total: d.total_space(),
            available: d.available_space(),
        })
        .filter(|v| v.total > 0)
        .collect();

    let mut procs: Vec<Process> = sys
        .processes()
        .iter()
        .map(|(pid, p)| Process {
            pid: pid.as_u32(),
            name: p.name().to_string_lossy().into_owned(),
            cpu: p.cpu_usage(),
            memory: p.memory(),
        })
        .collect();
    procs.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
    procs.truncate(8);

    let load = System::load_average();
    let cpu_count = sys.cpus().len();

    let mut status = Status {
        host: System::host_name().unwrap_or_else(|| "unknown".into()),
        os: System::long_os_version().unwrap_or_else(|| "macOS".into()),
        kernel: System::kernel_version().unwrap_or_default(),
        uptime_secs: System::uptime(),
        cpu_count,
        cpu_usage: sys.global_cpu_usage(),
        load: [load.one, load.five, load.fifteen],
        mem_total: sys.total_memory(),
        mem_used: sys.used_memory(),
        swap_total: sys.total_swap(),
        swap_used: sys.used_swap(),
        volumes,
        top_processes: procs,
        health: Vec::new(),
    };
    status.health = diagnose(&status);
    status
}

/// Turn readings into findings.
pub fn diagnose(s: &Status) -> Vec<Finding> {
    let mut out = Vec::new();

    for v in &s.volumes {
        let free_gb = v.available as f64 / 1024.0 / 1024.0 / 1024.0;
        let level = if free_gb < 5.0 {
            Level::Critical
        } else if free_gb < 15.0 {
            Level::Warn
        } else {
            Level::Ok
        };
        if level != Level::Ok {
            out.push(Finding {
                level,
                subject: format!("disk {}", v.mount.display()),
                detail: format!(
                    "{:.1} GB free ({:.0}% used)",
                    free_gb,
                    v.used_pct()
                ),
            });
        }
    }

    if s.mem_total > 0 {
        let pct = s.mem_used as f64 / s.mem_total as f64 * 100.0;
        if pct > 90.0 {
            out.push(Finding {
                level: Level::Warn,
                subject: "memory".into(),
                detail: format!("{pct:.0}% in use"),
            });
        }
    }

    if s.swap_total > 0 {
        let pct = s.swap_used as f64 / s.swap_total as f64 * 100.0;
        if pct > 50.0 {
            out.push(Finding {
                level: Level::Warn,
                subject: "swap".into(),
                detail: format!("{pct:.0}% of swap in use — memory pressure"),
            });
        }
    }

    if s.cpu_count > 0 && s.load[0] > s.cpu_count as f64 * 1.5 {
        out.push(Finding {
            level: Level::Warn,
            subject: "load".into(),
            detail: format!("1-minute load {:.2} on {} cores", s.load[0], s.cpu_count),
        });
    }

    if out.is_empty() {
        out.push(Finding {
            level: Level::Ok,
            subject: "system".into(),
            detail: "nothing to report".into(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Status {
        Status {
            host: "t".into(),
            os: "macOS".into(),
            kernel: "0".into(),
            uptime_secs: 1,
            cpu_count: 8,
            cpu_usage: 1.0,
            load: [0.5, 0.5, 0.5],
            mem_total: 100,
            mem_used: 10,
            swap_total: 100,
            swap_used: 0,
            volumes: vec![],
            top_processes: vec![],
            health: vec![],
        }
    }

    #[test]
    fn a_nearly_full_disk_is_critical() {
        let mut s = base();
        s.volumes.push(Volume {
            mount: "/".into(),
            total: 500 * 1024 * 1024 * 1024,
            available: 2 * 1024 * 1024 * 1024,
        });
        let f = diagnose(&s);
        assert!(f.iter().any(|f| f.level == Level::Critical));
    }

    #[test]
    fn a_healthy_machine_reports_ok() {
        let mut s = base();
        s.volumes.push(Volume {
            mount: "/".into(),
            total: 500 * 1024 * 1024 * 1024,
            available: 300 * 1024 * 1024 * 1024,
        });
        let f = diagnose(&s);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].level, Level::Ok);
    }

    #[test]
    fn swap_pressure_is_flagged() {
        let mut s = base();
        s.swap_used = 80;
        assert!(diagnose(&s).iter().any(|f| f.subject == "swap"));
    }

    #[test]
    fn volume_percentages_do_not_divide_by_zero() {
        let v = Volume {
            mount: "/".into(),
            total: 0,
            available: 0,
        };
        assert_eq!(v.used_pct(), 0.0);
    }
}
