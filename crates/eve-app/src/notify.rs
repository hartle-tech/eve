//! Notification permission, asked the way macOS actually expects.
//!
//! `tauri-plugin-notification` is a dead end on this platform: it answers
//! `Granted` without asking, `request_permission()` answers `Granted`
//! immediately and shows nothing, and even delivering with `.show()` leaves the
//! app unregistered. The proof was usernoted's own store — 114 applications
//! registered and eve not among them, before or after all three.
//!
//! So this calls `UNUserNotificationCenter` directly. That is the API macOS
//! raises the prompt from, and registering with it is what makes eve appear in
//! System Settings › Notifications at all.

use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use objc2_foundation::NSError;
use objc2_user_notifications::{
    UNAuthorizationOptions, UNAuthorizationStatus, UNNotificationSettings,
    UNUserNotificationCenter,
};

/// What macOS currently thinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    /// Never asked. This is the state that means the prompt has not been shown.
    NotDetermined,
    Granted,
    Denied,
    /// Asked and answered, but the app is not bundled or the centre is
    /// unavailable — treated as unknown rather than guessed at.
    Unavailable,
}

/// Raise the real permission prompt, and return **immediately**.
///
/// Call this on the main thread; wait for `rx` somewhere else. That split is
/// the whole point of the function.
///
/// The obvious shape — ask and block, all on the main thread — is what made
/// "Ask me now" do nothing at all. `requestAuthorizationWithOptions` returns
/// at once and the answer arrives later on a queue of macOS's choosing, so
/// blocking the main thread waiting for it holds the run loop for the entire
/// timeout. Nothing draws, the dialog never appears, the completion never
/// runs, and after sixty seconds eve reports that macOS did not answer — a
/// deadlock wearing a timeout's clothes.
pub fn begin_request(tx: mpsc::Sender<Authorization>) {
    let Some(center) = current_center() else {
        let _ = tx.send(Authorization::Unavailable);
        return;
    };

    let handler = RcBlock::new(move |granted: objc2::runtime::Bool, _err: *mut NSError| {
        let _ = tx.send(if granted.as_bool() {
            Authorization::Granted
        } else {
            Authorization::Denied
        });
    });

    // Alert and sound is what a cleanup notification needs; badge would put a
    // number on the Dock icon that nothing ever clears.
    let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
    center.requestAuthorizationWithOptions_completionHandler(options, &handler);
}

/// Whether macOS will still show a prompt at all.
///
/// Once the user has answered, `requestAuthorization` returns the stored
/// answer without any dialog, for ever. At that point the only thing that can
/// change the permission is System Settings — so a button labelled "Ask me
/// now" has to stop asking and start pointing.
pub fn can_still_ask() -> bool {
    status() == Authorization::NotDetermined
}

/// What macOS already decided, without asking.
pub fn status() -> Authorization {
    let Some(center) = current_center() else {
        return Authorization::Unavailable;
    };

    let (tx, rx) = mpsc::channel::<isize>();
    let handler = RcBlock::new(move |settings: core::ptr::NonNull<UNNotificationSettings>| {
        let status = unsafe { settings.as_ref().authorizationStatus() };
        let _ = tx.send(status.0);
    });
    center.getNotificationSettingsWithCompletionHandler(&handler);

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(v) if v == UNAuthorizationStatus::Authorized.0 => Authorization::Granted,
        Ok(v) if v == UNAuthorizationStatus::Provisional.0 => Authorization::Granted,
        Ok(v) if v == UNAuthorizationStatus::Denied.0 => Authorization::Denied,
        Ok(v) if v == UNAuthorizationStatus::NotDetermined.0 => Authorization::NotDetermined,
        _ => Authorization::Unavailable,
    }
}

/// `currentNotificationCenter` throws for a process that is not a proper
/// bundle, which is exactly what the command-line tool is — so this is
/// deliberately fallible rather than a panic waiting for the wrong caller.
fn current_center() -> Option<objc2::rc::Retained<UNUserNotificationCenter>> {
    if !eve_core::permissions::running_as_bundle() {
        return None;
    }
    Some(UNUserNotificationCenter::currentNotificationCenter())
}
