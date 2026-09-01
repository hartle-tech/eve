//! What root is willing to consider.
//!
//! The privileged worker re-runs the whole funnel, but the funnel alone is too
//! wide a grant: it would let any caller holding the escalation hand root a
//! hand-written plan pointing anywhere eve's protection rules happen not to
//! cover. This narrows that to *operations eve itself would have generated*,
//! re-derived by root from its own view of the disk.
//!
//! It lives here rather than in either binary because **both** of them are the
//! privileged peer. The CLI has always been; the app became one when the window
//! learned to raise the macOS administrator prompt, and for one release it had
//! no worker branch at all — so elevating the app ran `eve __worker`, fell
//! through to Tauri, and opened a second window instead of executing the plan.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub struct CatalogAuthorizer {
    /// category key -> the exact set of paths that category generates.
    allowed: HashMap<String, HashSet<PathBuf>>,
    /// The invoking user's Trash, for the shape rule below.
    trash: PathBuf,
}

impl CatalogAuthorizer {
    pub fn build() -> Self {
        // Built from the *invoking* user's home, not root's. Under sudo,
        // dirs::home_dir() is /var/root and every category would resolve to
        // paths that do not exist, refusing everything.
        let home = eve_core::privilege::invoking_user_home();
        let mut allowed: HashMap<String, HashSet<PathBuf>> = HashMap::new();

        for cat in eve_catalog::catalog_for(&home) {
            let entry = allowed.entry(cat.key.to_string()).or_default();
            for op in crate::clean::build_operations(&cat, &home) {
                entry.insert(eve_core::path::normalize(&op.path));
            }
        }

        // Uninstall operations are not catalog categories, so without this
        // root refused every one of them — the privileged path existed and
        // could not have worked. Root re-derives the removal plan for each
        // installed application from its own view and authorizes only those
        // paths: an actual bundle that is actually installed, plus the
        // leftovers that engine itself would offer. A hand-written plan
        // pointing anywhere else is still refused.
        for app in crate::uninstall::list_apps(&[]) {
            let plan = crate::uninstall::plan(&app, &home);
            for op in crate::uninstall::plan_to_operations(&plan) {
                allowed
                    .entry(op.category.clone())
                    .or_default()
                    .insert(eve_core::path::normalize(&op.path));
            }
        }

        CatalogAuthorizer {
            allowed,
            trash: eve_core::path::normalize(&home.join(".Trash")),
        }
    }
}

impl eve_core::privilege::PlanAuthorizer for CatalogAuthorizer {
    fn authorizes(&self, op: &eve_core::Operation) -> bool {
        if self
            .allowed
            .get(&op.category)
            .is_some_and(|paths| paths.contains(&eve_core::path::normalize(&op.path)))
        {
            return true;
        }

        // Enumeration is not always available to the privileged side.
        //
        // **Elevation does not confer Full Disk Access.** The elevated process
        // is a different TCC subject, and it is refused `~/.Trash` outright —
        // `ls` there returns "Operation not permitted" for root, while
        // `~/Library/Caches` reads fine. So root could not list the Trash, its
        // allowed set for that category came back empty, and it refused the
        // very operation the user had just authenticated for.
        //
        // Verified by shape instead, which needs no read: a direct child of
        // the invoking user's own Trash. That is exactly as tight — the only
        // thing it can ever authorise is emptying that user's Trash — and it
        // does not depend on a permission root turns out not to have.
        if op.category == "trash" {
            let path = eve_core::path::normalize(&op.path);
            return path.parent() == Some(self.trash.as_path());
        }

        false
    }
}
