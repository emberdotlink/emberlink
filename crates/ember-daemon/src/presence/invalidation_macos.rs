//! macOS lock/sleep invalidation for the daemon's interactive presence lane.
//!
//! The accepted ADR 139 posture is demand-pinned interactive unlock. On macOS,
//! an OS-level screen lock or system sleep must hard-lock that lane
//! immediately instead of waiting for the grace-window poller.

use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, anyhow};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

const SCREEN_LOCK_NOTIFICATION_NAME: &[u8] = b"com.apple.screenIsLocked\0";
const SCREEN_LOCK_POLL_MS: i32 = 200;
const SLEEP_RUN_LOOP_SLICE_SECS: CFTimeInterval = 0.25;
const NOTIFY_STATUS_OK: u32 = 0;
const IO_OBJECT_NULL: u32 = 0;
const KIO_MESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xe0000270;
const KIO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xe0000280;

type InvalidationCallback = Arc<dyn Fn(MacosPresenceEvent) + Send + Sync + 'static>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MacosPresenceEvent {
    ScreenLocked,
    SystemWillSleep,
}

impl MacosPresenceEvent {
    fn as_str(self) -> &'static str {
        match self {
            MacosPresenceEvent::ScreenLocked => "screen_locked",
            MacosPresenceEvent::SystemWillSleep => "system_will_sleep",
        }
    }
}

/// Drop-guard for macOS presence invalidation subscriptions.
pub struct MacosInvalidationWatcher {
    stop: Arc<AtomicBool>,
    dispatcher: Option<tokio::task::JoinHandle<()>>,
    screen_lock_worker: Option<JoinHandle<()>>,
    sleep_worker: Option<JoinHandle<()>>,
}

impl MacosInvalidationWatcher {
    /// Start both macOS invalidation sources:
    /// - screen lock via Darwin notify
    /// - system sleep via IOKit power notifications
    ///
    /// If one source fails to register, the other still runs. Startup fails
    /// only when both sources fail.
    pub async fn start() -> anyhow::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = unbounded_channel();
        let invalidate: InvalidationCallback = Arc::new(|event| {
            crate::trust::presence::invalidate_for_os_presence_event(event.as_str());
        });
        let dispatcher = spawn_dispatcher(rx, invalidate);

        let screen_lock_worker = match spawn_screen_lock_worker(tx.clone(), Arc::clone(&stop)) {
            Ok(handle) => Some(handle),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "macOS presence invalidation: failed to subscribe to screen-lock notifications"
                );
                None
            }
        };

        let sleep_worker = match spawn_sleep_worker(tx, Arc::clone(&stop)) {
            Ok(handle) => Some(handle),
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "macOS presence invalidation: failed to subscribe to system sleep notifications"
                );
                None
            }
        };

        if screen_lock_worker.is_none() && sleep_worker.is_none() {
            stop.store(true, Ordering::Release);
            dispatcher.abort();
            return Err(anyhow!(
                "macOS presence invalidation could not register any OS event sources"
            ));
        }

        Ok(Self {
            stop,
            dispatcher: Some(dispatcher),
            screen_lock_worker,
            sleep_worker,
        })
    }

    #[cfg(test)]
    fn start_for_test(
        rx: UnboundedReceiver<MacosPresenceEvent>,
        invalidate: InvalidationCallback,
    ) -> MacosInvalidationWatcher {
        let stop = Arc::new(AtomicBool::new(false));
        let dispatcher = spawn_dispatcher(rx, invalidate);
        MacosInvalidationWatcher {
            stop,
            dispatcher: Some(dispatcher),
            screen_lock_worker: None,
            sleep_worker: None,
        }
    }
}

impl Drop for MacosInvalidationWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.dispatcher.take() {
            handle.abort();
        }

        if let Some(handle) = self.screen_lock_worker.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.sleep_worker.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_dispatcher(
    mut rx: UnboundedReceiver<MacosPresenceEvent>,
    invalidate: InvalidationCallback,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        while let Some(event) = rx.recv().await {
            tracing::info!(
                event = event.as_str(),
                "macOS presence invalidation event received"
            );
            invalidate(event);
        }
    })
}

fn spawn_screen_lock_worker(
    tx: UnboundedSender<MacosPresenceEvent>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<JoinHandle<()>> {
    let mut notify_fd: libc::c_int = -1;
    let mut token: libc::c_int = -1;
    let status = unsafe {
        notify_register_file_descriptor(
            SCREEN_LOCK_NOTIFICATION_NAME.as_ptr().cast(),
            &mut notify_fd,
            0,
            &mut token,
        )
    };
    if status != NOTIFY_STATUS_OK {
        return Err(anyhow!(
            "notify_register_file_descriptor(com.apple.screenIsLocked) failed with status {status}"
        ));
    }
    if notify_fd < 0 || token < 0 {
        return Err(anyhow!(
            "notify_register_file_descriptor(com.apple.screenIsLocked) returned invalid fd/token"
        ));
    }

    thread::Builder::new()
        .name("emberd-macos-screen-lock".into())
        .spawn(move || {
            screen_lock_loop(notify_fd, token, tx, stop);
        })
        .context("spawn macOS screen-lock invalidation thread")
}

fn screen_lock_loop(
    notify_fd: RawFd,
    token: libc::c_int,
    tx: UnboundedSender<MacosPresenceEvent>,
    stop: Arc<AtomicBool>,
) {
    let mut poll_fd = libc::pollfd {
        fd: notify_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    while !stop.load(Ordering::Acquire) {
        let poll_rc = unsafe { libc::poll(&mut poll_fd, 1, SCREEN_LOCK_POLL_MS) };
        if poll_rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(
                error = %error,
                "macOS presence invalidation: screen-lock poll failed"
            );
            break;
        }
        if poll_rc == 0 {
            continue;
        }
        if poll_fd.revents & libc::POLLIN == 0 {
            continue;
        }

        let mut token_bytes = [0u8; std::mem::size_of::<u32>()];
        let read_rc = unsafe { libc::read(notify_fd, token_bytes.as_mut_ptr().cast(), 4) };
        if read_rc == 4 {
            let _ = tx.send(MacosPresenceEvent::ScreenLocked);
            continue;
        }

        if read_rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::warn!(
                error = %error,
                "macOS presence invalidation: screen-lock notify fd read failed"
            );
        } else {
            tracing::warn!(
                bytes = read_rc,
                "macOS presence invalidation: short read from screen-lock notify fd"
            );
        }
        break;
    }

    let status = unsafe { notify_cancel(token) };
    if status != NOTIFY_STATUS_OK {
        tracing::warn!(
            status,
            "macOS presence invalidation: notify_cancel for screen-lock token failed"
        );
    }
}

fn spawn_sleep_worker(
    tx: UnboundedSender<MacosPresenceEvent>,
    stop: Arc<AtomicBool>,
) -> anyhow::Result<JoinHandle<()>> {
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name("emberd-macos-system-sleep".into())
        .spawn(move || {
            // `run_sleep_worker` signals readiness via `ready_tx` BEFORE it
            // enters its until-shutdown run loop: `Ok(())` once IOKit power
            // registration succeeds, `Err(_)` on a registration failure. The
            // success path then loops until `stop`, so the readiness signal
            // must be sent from inside the worker — not after it returns —
            // otherwise startup would block forever waiting on a thread that
            // only exits at shutdown.
            if let Err(error) = run_sleep_worker(tx, stop, ready_tx) {
                tracing::warn!(
                    error = %error,
                    "macOS presence invalidation: system-sleep worker exited"
                );
            }
        })
        .context("spawn macOS system-sleep invalidation thread")?;

    match ready_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(message)) => {
            // Registration failed: the worker already returned before sending,
            // so this join is bounded.
            let _ = handle.join();
            Err(anyhow!(message))
        }
        Err(error) => {
            // No readiness within the window. The worker may be mid-registration
            // or already running its loop; joining here would deadlock on a
            // thread that only exits at shutdown. Detach and report — the Drop
            // guard sets `stop` and reaps it at teardown.
            Err(anyhow!(
                "timed out waiting for macOS system-sleep invalidation startup: {error}"
            ))
        }
    }
}

fn run_sleep_worker(
    tx: UnboundedSender<MacosPresenceEvent>,
    stop: Arc<AtomicBool>,
    ready: mpsc::SyncSender<Result<(), String>>,
) -> anyhow::Result<()> {
    let callback_ctx = Box::new(SleepCallbackContext {
        tx,
        root_port: AtomicU32::new(IO_OBJECT_NULL),
    });
    let callback_ctx_ptr = Box::into_raw(callback_ctx);

    let mut notification_port: IONotificationPortRef = std::ptr::null_mut();
    let mut notifier: IoObjectT = IO_OBJECT_NULL;
    let root_port = unsafe {
        IORegisterForSystemPower(
            callback_ctx_ptr.cast(),
            &mut notification_port,
            Some(system_power_callback),
            &mut notifier,
        )
    };

    if root_port == IO_OBJECT_NULL {
        unsafe {
            drop(Box::from_raw(callback_ctx_ptr));
        }
        let message = "IORegisterForSystemPower returned IO_OBJECT_NULL".to_string();
        let _ = ready.send(Err(message.clone()));
        return Err(anyhow!(message));
    }
    if notification_port.is_null() || notifier == IO_OBJECT_NULL {
        unsafe {
            let _ = IOServiceClose(root_port);
            drop(Box::from_raw(callback_ctx_ptr));
        }
        let message =
            "IORegisterForSystemPower returned incomplete notification handles".to_string();
        let _ = ready.send(Err(message.clone()));
        return Err(anyhow!(message));
    }

    let run_loop = unsafe { CFRunLoopGetCurrent() };
    let source = unsafe { IONotificationPortGetRunLoopSource(notification_port) };
    if run_loop.is_null() || source.is_null() {
        unsafe {
            let _ = IODeregisterForSystemPower(&mut notifier);
            IONotificationPortDestroy(notification_port);
            let _ = IOServiceClose(root_port);
            drop(Box::from_raw(callback_ctx_ptr));
        }
        let message = "IORegisterForSystemPower did not yield a valid CFRunLoop source".to_string();
        let _ = ready.send(Err(message.clone()));
        return Err(anyhow!(message));
    }

    unsafe {
        (*callback_ctx_ptr)
            .root_port
            .store(root_port, Ordering::Release);
        CFRunLoopAddSource(run_loop, source, kCFRunLoopDefaultMode);
    }

    // Registration is complete and the run-loop source is installed. Signal
    // readiness now, before the loop below blocks until shutdown.
    let _ = ready.send(Ok(()));

    while !stop.load(Ordering::Acquire) {
        unsafe {
            let _ = CFRunLoopRunInMode(kCFRunLoopDefaultMode, SLEEP_RUN_LOOP_SLICE_SECS, 1);
        }
    }

    unsafe {
        CFRunLoopRemoveSource(run_loop, source, kCFRunLoopDefaultMode);
        let _ = IODeregisterForSystemPower(&mut notifier);
        IONotificationPortDestroy(notification_port);
        let _ = IOServiceClose(root_port);
        drop(Box::from_raw(callback_ctx_ptr));
    }

    Ok(())
}

struct SleepCallbackContext {
    tx: UnboundedSender<MacosPresenceEvent>,
    root_port: AtomicU32,
}

unsafe extern "C" fn system_power_callback(
    refcon: *mut libc::c_void,
    _service: IoServiceT,
    message_type: u32,
    message_argument: *mut libc::c_void,
) {
    let Some(ctx_ptr) = (!refcon.is_null()).then_some(refcon.cast::<SleepCallbackContext>()) else {
        return;
    };
    let ctx = unsafe { &*ctx_ptr };
    let root_port = ctx.root_port.load(Ordering::Acquire);

    match message_type {
        KIO_MESSAGE_CAN_SYSTEM_SLEEP => {
            if root_port != IO_OBJECT_NULL {
                let _ = unsafe { IOAllowPowerChange(root_port, message_argument as isize) };
            }
        }
        KIO_MESSAGE_SYSTEM_WILL_SLEEP => {
            let _ = ctx.tx.send(MacosPresenceEvent::SystemWillSleep);
            if root_port != IO_OBJECT_NULL {
                let _ = unsafe { IOAllowPowerChange(root_port, message_argument as isize) };
            }
        }
        _ => {}
    }
}

type CFRunLoopRef = *const libc::c_void;
type CFRunLoopSourceRef = *const libc::c_void;
type CFRunLoopMode = *const libc::c_void;
type CFStringRef = *const libc::c_void;
type CFTimeInterval = f64;
type IONotificationPortRef = *mut libc::c_void;
type IoObjectT = u32;
type IoConnectT = u32;
type IoServiceT = u32;
type IOReturn = i32;
type Boolean = u8;

unsafe extern "C" {
    fn notify_register_file_descriptor(
        name: *const libc::c_char,
        notify_fd: *mut libc::c_int,
        flags: libc::c_int,
        out_token: *mut libc::c_int,
    ) -> u32;
    fn notify_cancel(token: libc::c_int) -> u32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFRunLoopDefaultMode: CFStringRef;

    fn CFRunLoopAddSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFRunLoopMode);
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRemoveSource(rl: CFRunLoopRef, source: CFRunLoopSourceRef, mode: CFRunLoopMode);
    fn CFRunLoopRunInMode(
        mode: CFRunLoopMode,
        seconds: CFTimeInterval,
        return_after_source_handled: Boolean,
    ) -> i32;
}

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IOAllowPowerChange(kernel_port: IoConnectT, notification_id: isize) -> IOReturn;
    fn IODeregisterForSystemPower(notifier: *mut IoObjectT) -> IOReturn;
    fn IONotificationPortDestroy(port: IONotificationPortRef);
    fn IONotificationPortGetRunLoopSource(port: IONotificationPortRef) -> CFRunLoopSourceRef;
    fn IORegisterForSystemPower(
        refcon: *mut libc::c_void,
        port_ref: *mut IONotificationPortRef,
        callback: Option<
            unsafe extern "C" fn(*mut libc::c_void, IoServiceT, u32, *mut libc::c_void),
        >,
        notifier: *mut IoObjectT,
    ) -> IoConnectT;
    fn IOServiceClose(connect: IoConnectT) -> IOReturn;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::rc::Rc;
    use std::sync::atomic::AtomicUsize;
    use tokio::runtime::Builder;
    use tokio::task::LocalSet;

    async fn wait_until_async(predicate: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(predicate(), "condition did not become true before timeout");
    }

    fn run_local_test(
        f: impl FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    ) {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let local = LocalSet::new();
        local.block_on(&runtime, async move {
            f().await;
        });
    }

    fn setup_presence_fixture() -> Rc<crate::infra::store::DaemonStore> {
        crate::trust::presence::reset_for_tests();
        crate::infra::interactive_unlock::reset_for_tests();
        let store = crate::infra::store::DaemonStore::open_in_memory().unwrap();
        store.set_vault(Rc::new(crate::infra::vault::Vault::new([0x66u8; 32])));
        let store = Rc::new(store);
        crate::trust::presence::register_store(Rc::clone(&store));
        crate::infra::interactive_unlock::register_store(Rc::clone(&store));
        crate::trust::presence::mark_unlocked();
        crate::infra::interactive_unlock::acquire_session_pin("sess-presence");
        store
    }

    // FLAKE (2026-05-27, observed under host-mode session-enrollment work,
    // pre-existing on origin/main): fails non-deterministically under full
    // `cargo test -p ember-daemon --lib` ordering with "screen lock must
    // hard-lock presence". Passes in isolation. Cause: shared
    // macOS-presence-watcher state on the test thread is mutated by a
    // sibling test in `crate::presence::*` and not reset before this
    // test reads it. Follow-up: scope `MacosInvalidationWatcher`'s
    // process-global handles per-test, or add an explicit reset step at
    // the top of every test in this module.
    #[test]
    fn screen_lock_event_invalidates_interactive_presence() {
        let _presence_test_guard = crate::trust::presence::test_state_guard();

        run_local_test(|| {
            Box::pin(async move {
                let store = setup_presence_fixture();
                let (tx, rx) = unbounded_channel();
                let watcher = MacosInvalidationWatcher::start_for_test(
                    rx,
                    Arc::new(|event| {
                        crate::trust::presence::invalidate_for_os_presence_event(event.as_str())
                    }),
                );

                tx.send(MacosPresenceEvent::ScreenLocked).unwrap();

                wait_until_async(|| crate::infra::interactive_unlock::pin_count() == 0).await;
                assert!(
                    store.vault().is_none(),
                    "screen lock must clear the live vault"
                );
                let (unlocked, idle) = crate::trust::presence::snapshot();
                assert!(!unlocked, "screen lock must hard-lock presence");
                assert!(idle.is_none());

                drop(watcher);
            })
        });
    }

    #[test]
    fn dispatcher_idle_does_not_spuriously_invalidate_presence() {
        let _presence_test_guard = crate::trust::presence::test_state_guard();

        run_local_test(|| {
            Box::pin(async move {
                let store = setup_presence_fixture();
                let (_tx, rx) = unbounded_channel::<MacosPresenceEvent>();
                let watcher = MacosInvalidationWatcher::start_for_test(
                    rx,
                    Arc::new(|event| {
                        crate::trust::presence::invalidate_for_os_presence_event(event.as_str())
                    }),
                );

                tokio::time::sleep(Duration::from_millis(150)).await;

                assert_eq!(
                    crate::infra::interactive_unlock::pin_count(),
                    1,
                    "ordinary watcher idle must not clear interactive unlock pins"
                );
                assert!(
                    store.vault().is_some(),
                    "ordinary watcher idle must not clear the live vault"
                );

                drop(watcher);
            })
        });
    }

    #[test]
    fn drop_stops_dispatch_before_late_events_arrive() {
        run_local_test(|| {
            Box::pin(async move {
                let delivered = Arc::new(AtomicUsize::new(0));
                let (tx, rx) = unbounded_channel();
                let delivered_for_callback = Arc::clone(&delivered);
                let watcher = MacosInvalidationWatcher::start_for_test(
                    rx,
                    Arc::new(move |_| {
                        delivered_for_callback.fetch_add(1, Ordering::AcqRel);
                    }),
                );

                drop(watcher);
                let _ = tx.send(MacosPresenceEvent::SystemWillSleep);
                tokio::time::sleep(Duration::from_millis(100)).await;

                assert_eq!(
                    delivered.load(Ordering::Acquire),
                    0,
                    "dropping the watcher must stop late event delivery"
                );
            })
        });
    }
}
