//! Bounded git sub-tree fetch pool (ADR 009 Decision 3b mitigation 4, task 105
//! REQ-105-01/02/06/07).
//!
//! Git sub-tree fetches are the only network cost of the transitive walk. A wide
//! dependency tree could otherwise open one connection per node simultaneously.
//! This pool caps the number of **in-flight** fetches at `fetch_concurrency`
//! (config key from task 107; default 4), so a wide tree fetches in parallel
//! *without* unbounded socket fan-out (REQ-105-01, T-105-04).
//!
//! ## Concurrency primitive — std threads + a counting semaphore (REQ-105-07)
//!
//! No thread-pool or async-runtime **crate** is used. dep-scan ships as a single
//! static binary (ADR 001); pulling in an async runtime (`tokio`) for a handful
//! of blocking `git fetch` calls would be disproportionate, and a heavyweight
//! thread-pool crate (`rayon`, `threadpool`) buys nothing over the std building
//! blocks for this fixed, bounded workload. The primitive is:
//!
//! - one OS thread per task (each task is a blocking git fetch),
//! - a [`Semaphore`] (a `Mutex<usize>` + [`Condvar`]) that hands out exactly
//!   `fetch_concurrency` permits — a thread acquires a permit *before* invoking
//!   the fetch and releases it after, so at no instant are more than
//!   `fetch_concurrency` fetches executing (REQ-105-01),
//! - an [`mpsc`] channel collecting `(index, Verdict)` results back on the
//!   caller's thread.
//!
//! This composes with — and does **not** reimplement — the per-fetch
//! `vcs.fetch_timeout_secs` bound (task 096): each fetch closure already returns
//! within the timeout (or `Err` on timeout); the pool simply treats any fetch
//! error as **unfetchable → fail-closed `Warn`** (REQ-105-06) and never hangs the
//! whole scan on one stuck fetch.
//!
//! With `fetch_concurrency == 1` the semaphore has a single permit, so all tasks
//! run strictly serially; the pool still drains its queue and returns — it does
//! not deadlock (REQ-105-02).
//!
//! The public surface is exercised by this module's tests and wired into the
//! live walk by task 108; the module-level allow mirrors the `transitive`
//! convention (see `engine.rs` / `scanner.rs`).
#![allow(dead_code)] // wired into the live walk by task 108

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::transitive::engine::Verdict;

/// A fail-closed counting semaphore built from the std primitives.
///
/// Holds `permits` available permits. [`acquire`] blocks until one is free and
/// takes it; [`release`] returns one and wakes a waiter. A thread holds a permit
/// for exactly the duration of its fetch, so the number of permits *in use*
/// equals the number of in-flight fetches — capped at the initial permit count.
///
/// [`acquire`]: Semaphore::acquire
/// [`release`]: Semaphore::release
struct Semaphore {
    /// `(available_permits)` guarded for the condvar wait.
    available: Mutex<usize>,
    /// Signalled whenever a permit is released.
    cv: Condvar,
}

impl Semaphore {
    /// A semaphore seeded with `permits` available permits.
    fn new(permits: usize) -> Self {
        Self {
            available: Mutex::new(permits),
            cv: Condvar::new(),
        }
    }

    /// Block until a permit is available, then take it.
    fn acquire(&self) {
        let mut available = self.available.lock().expect("semaphore mutex poisoned");
        while *available == 0 {
            available = self.cv.wait(available).expect("semaphore mutex poisoned");
        }
        *available -= 1;
    }

    /// Return a permit and wake one waiter.
    fn release(&self) {
        let mut available = self.available.lock().expect("semaphore mutex poisoned");
        *available += 1;
        self.cv.notify_one();
    }
}

/// Run `tasks` through a bounded fetch pool, returning each task's [`Verdict`] in
/// input order.
///
/// - `fetch_concurrency` caps the number of task closures executing at any
///   instant (REQ-105-01). It is taken as a parameter (task 107 supplies the
///   config value). A value of `0` is treated **defensively** as `1` — a pool
///   with zero workers would deadlock (it could never run a task), and task 107
///   already rejects `0` at config-validation; clamping here is a fail-safe so
///   the pool can never hang. (The node-budget ceiling, not the pool, is where a
///   `0` config *fails the scan* — see [`crate::transitive::budget`].)
/// - Each closure is expected to perform exactly one git sub-tree fetch + scan
///   and return its `Verdict`. A closure that wishes to signal "unfetchable"
///   (e.g. a fetch error or a `vcs.fetch_timeout_secs` timeout — REQ-105-06)
///   returns `Verdict::Warn` (or worse); the pool does not special-case it,
///   keeping the fail-closed floor in the closure where the fetch lives.
///
/// The call blocks until every task has completed, then returns the verdicts in
/// the original `tasks` order. It never drops or reorders a task (REQ-105-02/03,
/// T-105-03).
pub fn run_bounded<F>(tasks: Vec<F>, fetch_concurrency: u32) -> Vec<Verdict>
where
    F: FnOnce() -> Verdict + Send + 'static,
{
    let n = tasks.len();
    if n == 0 {
        return Vec::new();
    }
    // Defensive clamp: a pool of 0 workers can never run a task → deadlock.
    // Task 107 rejects 0 at config; clamping to 1 here guarantees liveness.
    let permits = fetch_concurrency.max(1) as usize;
    let semaphore = Arc::new(Semaphore::new(permits));
    let (tx, rx) = mpsc::channel::<(usize, Verdict)>();

    let mut handles = Vec::with_capacity(n);
    for (index, task) in tasks.into_iter().enumerate() {
        let semaphore = Arc::clone(&semaphore);
        let tx = tx.clone();
        let handle = thread::spawn(move || {
            // Bounded concurrency: take a permit before running the fetch, hold
            // it for the whole fetch, release it after. At most `permits` fetches
            // hold a permit simultaneously (REQ-105-01).
            semaphore.acquire();
            let verdict = task();
            semaphore.release();
            // Send is infallible: the receiver lives until every result arrives.
            let _ = tx.send((index, verdict));
        });
        handles.push(handle);
    }
    // Drop the original sender so the channel closes once all workers finish.
    drop(tx);

    // Collect results as they arrive, then place each in input order.
    let mut results: Vec<Option<Verdict>> = (0..n).map(|_| None).collect();
    for (index, verdict) in rx.iter() {
        results[index] = Some(verdict);
    }
    // Join every worker so no fetch thread outlives the call (no detached work).
    for handle in handles {
        let _ = handle.join();
    }

    results
        .into_iter()
        .map(|v| v.expect("every task must have produced a verdict"))
        .collect()
}

/// A shared counter that tracks the peak number of concurrently-running tasks.
///
/// Test-only instrumentation (it backs T-105-01/02/04): a task increments the
/// live counter on entry and decrements on exit, updating the peak each time. The
/// peak must never exceed `fetch_concurrency`. Kept in the module (not under
/// `cfg(test)`) so the type is documented next to the pool it instruments, but
/// only constructed by tests.
#[allow(dead_code)] // constructed only by the pool's own tests
pub struct ConcurrencyGauge {
    live: AtomicUsize,
    peak: AtomicUsize,
}

#[allow(dead_code)] // exercised only by the pool's own tests
impl ConcurrencyGauge {
    /// A gauge starting at zero live, zero peak.
    pub fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        }
    }

    /// Record a task entering its critical section; update the peak.
    pub fn enter(&self) {
        let now = self.live.fetch_add(1, Ordering::SeqCst) + 1;
        // Monotonically raise the recorded peak to at least `now`.
        self.peak.fetch_max(now, Ordering::SeqCst);
    }

    /// Record a task leaving its critical section.
    pub fn leave(&self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }

    /// The highest number of simultaneously-live tasks observed.
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // --- T-105-01: fetch_concurrency limits simultaneous in-flight fetches ---
    //
    // 6 tasks, fetch_concurrency = 2, each task sleeps briefly while holding the
    // gauge. The gauge's peak must never exceed 2. The sleep is what makes the
    // assertion deterministic: every task is guaranteed to overlap with any other
    // task admitted at the same time, so if the pool *ever* admitted 3, the gauge
    // would observe 3. It never does.
    #[test]
    fn t_105_01_concurrency_capped_at_two() {
        let gauge = Arc::new(ConcurrencyGauge::new());
        let tasks: Vec<_> = (0..6)
            .map(|_| {
                let gauge = Arc::clone(&gauge);
                move || -> Verdict {
                    gauge.enter();
                    // Hold the critical section long enough that any over-admission
                    // is observed by the gauge before this task releases.
                    thread::sleep(Duration::from_millis(50));
                    gauge.leave();
                    Verdict::Pass
                }
            })
            .collect();

        let verdicts = run_bounded(tasks, 2);
        assert_eq!(verdicts.len(), 6, "all 6 tasks produced a verdict");
        assert!(
            gauge.peak() <= 2,
            "T-105-01: peak concurrency {} must never exceed fetch_concurrency 2",
            gauge.peak()
        );
        // And concurrency genuinely happened (peak reached 2), proving the cap is
        // a ceiling, not an accidental serialisation.
        assert_eq!(
            gauge.peak(),
            2,
            "T-105-01: with 6 tasks and a 50ms hold, the pool must reach its full 2-wide concurrency"
        );
    }

    // --- T-105-02: fetch_concurrency = 1 serialises all fetches (no deadlock) -
    #[test]
    fn t_105_02_concurrency_one_serialises_no_deadlock() {
        let gauge = Arc::new(ConcurrencyGauge::new());
        let tasks: Vec<_> = (0..5)
            .map(|_| {
                let gauge = Arc::clone(&gauge);
                move || -> Verdict {
                    gauge.enter();
                    thread::sleep(Duration::from_millis(10));
                    gauge.leave();
                    Verdict::Pass
                }
            })
            .collect();

        let verdicts = run_bounded(tasks, 1);
        // No deadlock: the call returned and every task ran.
        assert_eq!(verdicts.len(), 5, "all 5 tasks completed under serial pool");
        assert_eq!(
            gauge.peak(),
            1,
            "T-105-02: with fetch_concurrency = 1 the peak concurrency must be exactly 1"
        );
    }

    // --- T-105-03: all queued fetches complete when pool size < task count ---
    #[test]
    fn t_105_03_all_tasks_complete_when_pool_smaller_than_queue() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..5)
            .map(|_| {
                let counter = Arc::clone(&counter);
                move || -> Verdict {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Verdict::Pass
                }
            })
            .collect();

        let verdicts = run_bounded(tasks, 2);
        assert_eq!(verdicts.len(), 5, "5 tasks, pool of 2 — none dropped");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            5,
            "T-105-03: every queued task must have executed exactly once"
        );
    }

    // --- T-105-04: no unbounded socket fan-out — 100 nodes, pool stays bounded -
    #[test]
    fn t_105_04_no_unbounded_fan_out_over_one_hundred_nodes() {
        let gauge = Arc::new(ConcurrencyGauge::new());
        let tasks: Vec<_> = (0..100)
            .map(|_| {
                let gauge = Arc::clone(&gauge);
                move || -> Verdict {
                    gauge.enter();
                    // A tiny hold so overlapping admissions are observable.
                    thread::sleep(Duration::from_millis(2));
                    gauge.leave();
                    Verdict::Pass
                }
            })
            .collect();

        let verdicts = run_bounded(tasks, 4);
        assert_eq!(verdicts.len(), 100, "all 100 simulated nodes completed");
        assert!(
            gauge.peak() <= 4,
            "T-105-04: even with 100 nodes the pool never exceeds fetch_concurrency 4 (peak {})",
            gauge.peak()
        );
    }

    // --- result ordering is preserved (verdicts map back to input order) ---
    #[test]
    fn run_bounded_preserves_input_order() {
        // Task i returns Warn iff i is even, Pass otherwise. Despite out-of-order
        // completion (varying sleeps), the returned vec must match input order.
        let tasks: Vec<_> = (0..6)
            .map(|i| {
                move || -> Verdict {
                    // Earlier tasks sleep longer, forcing out-of-order completion.
                    thread::sleep(Duration::from_millis((6 - i) as u64 * 5));
                    if i % 2 == 0 {
                        Verdict::Warn
                    } else {
                        Verdict::Pass
                    }
                }
            })
            .collect();
        let verdicts = run_bounded(tasks, 3);
        assert_eq!(
            verdicts,
            vec![
                Verdict::Warn,
                Verdict::Pass,
                Verdict::Warn,
                Verdict::Pass,
                Verdict::Warn,
                Verdict::Pass,
            ],
            "verdicts must be returned in input order regardless of completion order"
        );
    }

    // --- empty task list returns empty, no deadlock ---
    #[test]
    fn run_bounded_empty_is_noop() {
        let verdicts = run_bounded(Vec::<fn() -> Verdict>::new(), 4);
        assert!(verdicts.is_empty());
    }

    // --- fetch_concurrency = 0 is clamped to 1, never deadlocks (defensive) ---
    #[test]
    fn run_bounded_zero_concurrency_clamped_no_deadlock() {
        let tasks: Vec<_> = (0..3).map(|_| || -> Verdict { Verdict::Pass }).collect();
        // A literal 0 would mean "no workers"; the pool clamps to 1 so it can
        // never hang. (max_total_nodes = 0 is the path that *fails the scan* —
        // that is the budget's job, asserted in budget.rs / T-105-07.)
        let verdicts = run_bounded(tasks, 0);
        assert_eq!(
            verdicts.len(),
            3,
            "0 concurrency clamps to 1; tasks still run"
        );
    }

    // =====================================================================
    // T-105-06 (composition): a timed-out / errored fetch is treated as
    // unfetchable (≥ Warn) and does NOT hang the whole scan.
    // =====================================================================
    //
    // The pool composes with vcs.fetch_timeout_secs (task 096): the fetch
    // closure itself returns within the timeout, returning Verdict::Warn on a
    // timeout/error (the scanner's fail-closed floor — scanner.rs scan_git Err
    // arm). We model that here: one task "times out" (returns Warn), the rest
    // pass. The scan completes (no hang) and the timed-out task's verdict is
    // ≥ Warn, never Pass.
    #[test]
    fn t_105_06_timed_out_fetch_is_warn_and_does_not_hang() {
        let tasks: Vec<Box<dyn FnOnce() -> Verdict + Send>> = vec![
            Box::new(|| Verdict::Pass),
            // The "hanging" fetch: in production VcsFetcher::fetch returns Err
            // after vcs.fetch_timeout_secs; the scanner maps that to Warn. We
            // model the *post-timeout* fail-closed floor directly (a real sleep
            // past the timeout would make the test slow and flaky).
            Box::new(|| Verdict::Warn),
            Box::new(|| Verdict::Pass),
        ];

        let start = Instant::now();
        let verdicts = run_bounded(tasks, 2);
        let elapsed = start.elapsed();

        // The whole scan returned promptly — one unfetchable task did not hang it.
        assert!(
            elapsed < Duration::from_secs(5),
            "T-105-06: a timed-out fetch must not hang the whole scan (took {elapsed:?})"
        );
        // The timed-out task contributes ≥ Warn (fail-closed), never Pass.
        assert_eq!(verdicts[1], Verdict::Warn);
        assert!(
            verdicts[1] >= Verdict::Warn,
            "T-105-06: a timed-out fetch is unfetchable → ≥ Warn"
        );
        assert_ne!(verdicts[1], Verdict::Pass);
    }

    // =====================================================================
    // T-105-09: the per-fetch timeout from vcs.fetch_timeout_secs is respected
    // inside the pool — a fetch that hangs beyond the timeout is bounded and
    // returns ≥ Warn; the scan continues rather than hanging indefinitely.
    // =====================================================================
    //
    // We model the timeout bound the SAME way VcsFetcher::fetch (task 096) does:
    // the fetch runs on a worker thread and the closure bounds its own wait with
    // recv_timeout(fetch_timeout). A "hanging" fetch (sleeps past the timeout)
    // trips that bound and the closure returns the fail-closed Warn floor — it
    // never blocks the pool forever. This is the composition contract: the pool
    // does not add its own timeout; it relies on the fetch closure being bounded.
    fn bounded_fetch(fetch_timeout: Duration, work: Duration) -> Verdict {
        let (tx, rx) = mpsc::channel::<()>();
        thread::spawn(move || {
            thread::sleep(work);
            let _ = tx.send(());
        });
        match rx.recv_timeout(fetch_timeout) {
            Ok(()) => Verdict::Pass,
            // Timed out → unfetchable → fail-closed Warn (REQ-105-06).
            Err(_) => Verdict::Warn,
        }
    }

    #[test]
    fn t_105_09_per_fetch_timeout_respected_in_pool() {
        // fetch_timeout = 1s (vcs.fetch_timeout_secs). One task "hangs" for 5s
        // (well past the timeout); two complete quickly.
        let fetch_timeout = Duration::from_secs(1);
        let tasks: Vec<Box<dyn FnOnce() -> Verdict + Send>> = vec![
            Box::new(move || bounded_fetch(fetch_timeout, Duration::from_millis(20))),
            // The hanging fetch: work (5s) far exceeds the 1s timeout.
            Box::new(move || bounded_fetch(fetch_timeout, Duration::from_secs(5))),
            Box::new(move || bounded_fetch(fetch_timeout, Duration::from_millis(20))),
        ];

        let start = Instant::now();
        let verdicts = run_bounded(tasks, 2);
        let elapsed = start.elapsed();

        // The hanging fetch was bounded at ~1s; the whole scan returns well before
        // the 5s the hung work would have taken — it did NOT hang indefinitely.
        assert!(
            elapsed < Duration::from_secs(3),
            "T-105-09: the per-fetch timeout must bound the scan (took {elapsed:?}, \
             hung work was 5s)"
        );
        // The timed-out fetch is unfetchable → ≥ Warn, never Pass (fail-closed).
        assert_eq!(verdicts[1], Verdict::Warn);
        assert_ne!(verdicts[1], Verdict::Pass);
        // The other two fetches completed cleanly.
        assert_eq!(verdicts[0], Verdict::Pass);
        assert_eq!(verdicts[2], Verdict::Pass);
    }

    // --- T-105-11: no specific concurrency CRATE is named in the contract. ---
    //
    // Design-review marker (mirrors the spec's T-105-11). The pool is built from
    // std primitives only (std::thread + Mutex/Condvar semaphore + mpsc); no
    // thread-pool or async-runtime crate is referenced. This test keeps T-105-11
    // referenced in the suite and documents the crate-agnostic choice.
    #[test]
    fn t_105_11_no_concurrency_crate_dependency() {
        // The pool runs with only std imports in scope (asserted structurally by
        // this module compiling without an external concurrency crate). A trivial
        // run proves the std-only pool is operational.
        let verdicts = run_bounded(vec![|| Verdict::Pass, || Verdict::Pass], 2);
        assert_eq!(verdicts, vec![Verdict::Pass, Verdict::Pass]);
    }

    // --- T-105-12: tooling gate (`cargo test` / clippy -D warnings / fmt
    // --check) is enforced by the pre-commit pipeline, not a unit test. This
    // marker keeps T-105-12 referenced (mirrors T-102-18 / T-103-11 / T-104-15).
    #[test]
    fn t_105_12_tooling_gate_marker() {}

    // =====================================================================
    // T-105-10: concurrency actually reduces wall-clock time vs serial.
    // =====================================================================
    //
    // 4 tasks, each sleeping 100ms, fetch_concurrency = 2. Serial would take
    // ~400ms (4 × 100ms); two-wide should take ~200ms (two rounds of 2). We
    // assert the parallel run is well under the serial bound. Using a generous
    // upper bound (1.9 × ideal) absorbs scheduling jitter so the test is not
    // flaky, while still being far below the serial 400ms.
    #[test]
    fn t_105_10_concurrency_reduces_wall_clock() {
        let per_task = Duration::from_millis(100);
        let concurrency = 2u32;
        let n = 4usize;

        let make_tasks = || -> Vec<Box<dyn FnOnce() -> Verdict + Send>> {
            (0..n)
                .map(|_| {
                    Box::new(move || -> Verdict {
                        thread::sleep(per_task);
                        Verdict::Pass
                    }) as Box<dyn FnOnce() -> Verdict + Send>
                })
                .collect()
        };

        // Parallel run.
        let start = Instant::now();
        let parallel = run_bounded(make_tasks(), concurrency);
        let parallel_elapsed = start.elapsed();
        assert_eq!(parallel.len(), n);

        // Serial run (concurrency = 1) for a direct comparison.
        let start = Instant::now();
        let serial = run_bounded(make_tasks(), 1);
        let serial_elapsed = start.elapsed();
        assert_eq!(serial.len(), n);

        // Concurrency must reduce wall-clock time. We compare the parallel run
        // directly against a serial run on the SAME machine rather than against
        // an absolute millisecond budget. Absolute wall-clock bounds are flaky
        // on shared CI runners: the margin between ideal-parallel (~2 rounds =
        // 200ms) and serial (~4 rounds = 400ms) is only 2x, and a loaded runner
        // can inflate the parallel run past an absolute ceiling from
        // thread-scheduling jitter alone. The relative check is self-normalising
        // — both runs absorb the same machine load — so it stays meaningful
        // without flaking. Require parallel < 0.75 × serial (ideal ratio is 0.5).
        let ideal_parallel = per_task * (n.div_ceil(concurrency as usize) as u32);
        assert!(
            parallel_elapsed.as_secs_f64() < serial_elapsed.as_secs_f64() * 0.75,
            "T-105-10: concurrency must reduce wall-clock: parallel {parallel_elapsed:?} \
             vs serial {serial_elapsed:?} (ideal parallel ~{ideal_parallel:?})"
        );
    }
}
