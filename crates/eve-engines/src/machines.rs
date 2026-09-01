//! Containers, virtual machines and emulators.
//!
//! These are the largest things on a developer's disk that no cache cleaner
//! looks at, because they are not caches — a container image store or a VM
//! disk is real state that somebody chose to create. eve's job here is to make
//! them *visible*, with sizes, and to be honest about what removing one costs.
//!
//! Nothing here is ever on by default and nothing is swept automatically. A
//! stale Android emulator and a VM holding a week of work look identical from
//! the filesystem's side, so the decision has to be the user's.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rayon::prelude::*;
use serde::Serialize;

/// What kind of thing is taking up the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachineKind {
    /// Container engine storage: images, layers, volumes.
    Containers,
    /// A full virtual machine's disk.
    VirtualMachine,
    /// A device emulator or simulator.
    Emulator,
}

impl MachineKind {
    pub fn title(self) -> &'static str {
        match self {
            MachineKind::Containers => "Container storage",
            MachineKind::VirtualMachine => "Virtual machines",
            MachineKind::Emulator => "Emulators and simulators",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Machine {
    pub kind: MachineKind,
    /// The product, as a person would name it.
    pub name: String,
    pub path: PathBuf,
    pub bytes: u64,
    /// False when the size is a floor rather than a total.
    pub complete: bool,
    /// What removing this actually costs, in the user's terms.
    pub cost: &'static str,
    /// The tool's own command, when there is a better way than deleting the
    /// directory. Reclaiming a container store with `rm -rf` leaves the engine
    /// believing images still exist.
    pub better_command: Option<&'static str>,
}

struct Candidate {
    kind: MachineKind,
    name: &'static str,
    rel: &'static str,
    cost: &'static str,
    better_command: Option<&'static str>,
}

const CANDIDATES: &[Candidate] = &[
    Candidate {
        kind: MachineKind::Containers,
        name: "Podman",
        rel: ".local/share/containers",
        cost: "Every image, layer and volume Podman holds. Images re-pull; volume data does not come back.",
        better_command: Some("podman system prune -a --volumes"),
    },
    Candidate {
        kind: MachineKind::Containers,
        name: "Docker Desktop",
        rel: "Library/Containers/com.docker.docker/Data/vms",
        cost: "Docker's whole virtual disk — images, containers and volumes together.",
        better_command: Some("docker system prune -a --volumes"),
    },
    Candidate {
        kind: MachineKind::Containers,
        name: "Colima",
        rel: ".colima",
        cost: "Colima's VM and its container storage.",
        better_command: Some("colima delete"),
    },
    Candidate {
        kind: MachineKind::Containers,
        name: "OrbStack",
        rel: ".orbstack",
        cost: "OrbStack's machines and container storage.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::Containers,
        name: "minikube",
        rel: ".minikube",
        cost: "The local Kubernetes cluster and its images. Recreated by `minikube start`.",
        better_command: Some("minikube delete --all"),
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "Lima",
        rel: ".lima",
        cost: "Every Lima VM and its disk.",
        better_command: Some("limactl delete --all"),
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "UTM",
        rel: "Library/Containers/com.utmapp.UTM/Data/Documents",
        cost: "Your UTM virtual machines and everything inside them.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "Parallels",
        rel: "Parallels",
        cost: "Your Parallels virtual machines and everything inside them.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "VMware Fusion",
        rel: "Virtual Machines.localized",
        cost: "Your Fusion virtual machines and everything inside them.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "VirtualBox",
        rel: "VirtualBox VMs",
        cost: "Your VirtualBox machines and everything inside them.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "Vagrant boxes",
        rel: ".vagrant.d/boxes",
        cost: "Downloaded base boxes. Re-downloaded on the next `vagrant up`.",
        better_command: Some("vagrant box prune"),
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "Multipass",
        rel: "Library/Application Support/multipass",
        cost: "Every Multipass instance and its disk.",
        better_command: Some("multipass delete --all --purge"),
    },
    Candidate {
        kind: MachineKind::VirtualMachine,
        name: "Claude sandbox VMs",
        rel: "Library/Application Support/Claude/vm_bundles",
        cost: "Cached sandbox images. Regenerated on demand.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::Emulator,
        name: "Android emulators",
        rel: ".android/avd",
        cost: "Every Android virtual device, including anything installed inside them.",
        better_command: None,
    },
    Candidate {
        kind: MachineKind::Emulator,
        name: "iOS simulators",
        rel: "Library/Developer/CoreSimulator/Devices",
        cost: "Every simulated device and its installed apps. Xcode recreates them empty.",
        better_command: Some("xcrun simctl delete unavailable"),
    },
];

/// Everything present, biggest first.
///
/// Measured in parallel: these are the largest trees on the disk, and walking
/// fifteen of them in series is the difference between a screen that opens and
/// one that hangs.
pub fn survey(home: &Path) -> Vec<Machine> {
    let mut found: Vec<Machine> = CANDIDATES
        .par_iter()
        .filter_map(|c| {
            let path = home.join(c.rel);
            if !path.exists() {
                return None;
            }
            let m = eve_core::size::measure(&path, Duration::from_secs(20));
            // A directory the tool created but never filled is noise.
            if m.bytes < 8 * 1024 * 1024 {
                return None;
            }
            Some(Machine {
                kind: c.kind,
                name: c.name.to_string(),
                path,
                bytes: m.bytes,
                complete: m.complete,
                cost: c.cost,
                better_command: c.better_command,
            })
        })
        .collect();

    found.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    found
}

/// Turn selections into funnel operations.
///
/// `NeverAuto`, which is stronger than the disk browser's `Destructive`: an
/// unattended run must never reach a virtual machine, whatever else is
/// configured. A VM disk is somebody's working environment, not a cache, and
/// there is no version of "eve tidied it up at 3am" that is acceptable.
pub fn to_operations(paths: &[PathBuf]) -> Vec<eve_core::Operation> {
    paths
        .iter()
        .map(|p| {
            eve_core::Operation::new("machines", p.clone(), eve_core::RiskTier::NeverAuto)
                .with_disposition(eve_core::executor::Disposition::Trash)
                .with_exemptions(vec![p.clone()])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_what_exists_and_is_worth_mentioning_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();

        // Present and substantial.
        let podman = home.join(".local/share/containers");
        std::fs::create_dir_all(&podman).unwrap();
        std::fs::write(podman.join("blob"), vec![0u8; 12 * 1024 * 1024]).unwrap();

        // Present but empty — a tool that ran once and made a directory.
        std::fs::create_dir_all(home.join(".colima")).unwrap();

        let found = survey(home);
        let names: Vec<&str> = found.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["Podman"], "empty stores should not be listed");
        assert_eq!(found[0].kind, MachineKind::Containers);
        assert!(found[0].better_command.is_some(), "prune is safer than rm -rf");
    }

    #[test]
    fn biggest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        for (rel, mb) in [(".local/share/containers", 12), (".android/avd", 40)] {
            let d = home.join(rel);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("blob"), vec![0u8; mb * 1024 * 1024]).unwrap();
        }
        let found = survey(home);
        assert_eq!(found[0].name, "Android emulators");
    }

    /// A virtual machine is somebody's working environment. No unattended run
    /// may ever reach one, whatever else the user has switched on.
    #[test]
    fn machines_are_never_touched_unattended() {
        let ops = to_operations(&[PathBuf::from("/Users/tester/.lima")]);
        assert_eq!(ops[0].tier, eve_core::RiskTier::NeverAuto);
        assert!(!ops[0].tier.allowed_unattended());
        assert!(ops[0].tier.needs_typed_confirmation());
        assert_eq!(
            ops[0].disposition,
            eve_core::executor::Disposition::Trash,
            "a VM disk must stay recoverable"
        );
    }
}
