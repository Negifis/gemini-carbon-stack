use std::collections::HashSet;
use std::env;
use std::ffi::{c_char, c_double, c_int, c_void, CStr, CString};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn now_sec() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn format_iso_utc(ts: f64) -> String {
    let secs = if ts > 0.0 { ts as i64 } else { 0 };
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, m, d, hour, min, sec)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y_adj = y - if m <= 2 { 1 } else { 0 };
    let era = if y_adj >= 0 { y_adj } else { y_adj - 399 } / 400;
    let yoe = (y_adj - era * 400) as u32;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i64) - 719468
}

pub fn parse_iso_ts(raw: &str) -> f64 {
    let s = raw.trim();
    if s.is_empty() {
        return 0.0;
    }
    if let Ok(num) = s.parse::<f64>() {
        return if num.is_finite() && num > 0.0 { num } else { 0.0 };
    }
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return 0.0;
    }
    if !bytes[..19].is_ascii()
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b't' && bytes[10] != b' ')
    {
        return 0.0;
    }
    let year: i64 = match s[0..4].parse() {
        Ok(v) => v,
        Err(_) => return 0.0,
    };
    let month: u32 = match s[5..7].parse() {
        Ok(v) if (1..=12).contains(&v) => v,
        _ => return 0.0,
    };
    let day: u32 = match s[8..10].parse() {
        Ok(v) if (1..=31).contains(&v) => v,
        _ => return 0.0,
    };
    let hour: i64 = match s[11..13].parse() {
        Ok(v) if (0..=23).contains(&v) => v,
        _ => return 0.0,
    };
    let min: i64 = match s[14..16].parse() {
        Ok(v) if (0..=59).contains(&v) => v,
        _ => return 0.0,
    };
    let sec: i64 = match s[17..19].parse() {
        Ok(v) if (0..=60).contains(&v) => v,
        _ => return 0.0,
    };
    let rest = &s[19..];
    let mut frac = 0.0f64;
    let mut tz_part = rest;
    if let Some(after_dot) = rest.strip_prefix('.') {
        let digits_len = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len > 0 {
            let take_n = digits_len.min(9);
            if let Ok(fval) = after_dot[..take_n].parse::<u64>() {
                frac = (fval as f64) / 10f64.powi(take_n as i32);
            }
        }
        tz_part = &after_dot[digits_len..];
    }
    let tz_trim = tz_part.trim();
    if tz_trim.is_empty() {
        // INVARIANT: Naive strings (e.g. `board.jsonl` "YYYY-MM-DD HH:MM:SS") are local wall-clock time, matching Python `datetime.timestamp()`.
        #[cfg(windows)]
        {
            if let Some((uy, um, ud, uh, umin, us)) =
                win_ffi::local_civil_to_utc(year, month, day, hour, min, sec)
            {
                let udays = days_from_civil(uy, um, ud);
                let uepoch = udays * 86400 + uh * 3600 + umin * 60 + us;
                return (uepoch as f64) + frac;
            }
        }
        #[cfg(not(windows))]
        {
            if let Some(uepoch) = posix_local_civil_to_epoch(year, month, day, hour, min, sec) {
                return (uepoch as f64) + frac;
            }
        }
    }
    let mut offset_secs: i64 = 0;
    if !tz_trim.is_empty() && tz_trim != "Z" && tz_trim != "z" {
        let sign: i64 = if tz_trim.starts_with('+') {
            1
        } else if tz_trim.starts_with('-') {
            -1
        } else {
            return 0.0;
        };
        let off_body = &tz_trim[1..];
        if !off_body.is_ascii() {
            return 0.0;
        }
        let (oh_str, om_str) = if let Some((a, b)) = off_body.split_once(':') {
            (a, b)
        } else if off_body.len() == 4 {
            (&off_body[0..2], &off_body[2..4])
        } else if off_body.len() == 2 {
            (off_body, "00")
        } else {
            return 0.0;
        };
        let oh: i64 = match oh_str.parse() {
            Ok(v) => v,
            Err(_) => return 0.0,
        };
        let om: i64 = match om_str.parse() {
            Ok(v) => v,
            Err(_) => return 0.0,
        };
        offset_secs = sign * (oh * 3600 + om * 60);
    }
    let days = days_from_civil(year, month, day);
    let epoch_secs = days * 86400 + hour * 3600 + min * 60 + sec - offset_secs;
    (epoch_secs as f64) + frac
}

#[cfg(not(windows))]
fn posix_local_civil_to_epoch(
    year: i64,
    month: u32,
    day: u32,
    hour: i64,
    min: i64,
    sec: i64,
) -> Option<i64> {
    #[repr(C)]
    struct PosixTm {
        tm_sec: c_int,
        tm_min: c_int,
        tm_hour: c_int,
        tm_mday: c_int,
        tm_mon: c_int,
        tm_year: c_int,
        tm_wday: c_int,
        tm_yday: c_int,
        tm_isdst: c_int,
        tm_gmtoff: isize,
        tm_zone: *const c_char,
    }
    extern "C" {
        fn mktime(tm: *mut PosixTm) -> isize;
    }
    let mut tm = PosixTm {
        tm_sec: sec as c_int,
        tm_min: min as c_int,
        tm_hour: hour as c_int,
        tm_mday: day as c_int,
        tm_mon: (month as c_int) - 1,
        tm_year: (year as c_int) - 1900,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: -1,
        tm_gmtoff: 0,
        tm_zone: ptr::null(),
    };
    // SAFETY: Standard POSIX `mktime` converts local civil `struct tm` to epoch seconds.
    let res = unsafe { mktime(&mut tm) };
    if res == -1 { None } else { Some(res as i64) }
}

#[cfg(windows)]
mod win_ffi {
    use super::*;

    pub type Handle = *mut c_void;
    pub type HModule = *mut c_void;
    pub type FarProc = *const c_void;
    pub type Dword = u32;
    pub type Bool = i32;

    pub const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
    pub const CREATE_NO_WINDOW: Dword = 0x08000000;
    pub const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: c_int = 9;
    pub const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Dword = 0x00002000;
    pub const TH32CS_SNAPPROCESS: Dword = 0x00000002;
    pub const PROCESS_TERMINATE: Dword = 0x0001;
    pub const PROCESS_SET_QUOTA: Dword = 0x0100;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: Dword = 0x00000400;
    pub const INVALID_FILE_ATTRIBUTES: Dword = 0xFFFFFFFF;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct IoCounters {
        pub read_operation_count: u64,
        pub write_operation_count: u64,
        pub other_operation_count: u64,
        pub read_transfer_count: u64,
        pub write_transfer_count: u64,
        pub other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct JobObjectBasicLimitInformation {
        pub per_process_user_time_limit: i64,
        pub per_job_user_time_limit: i64,
        pub limit_flags: Dword,
        pub minimum_working_set_size: usize,
        pub maximum_working_set_size: usize,
        pub active_process_limit: Dword,
        pub affinity: usize,
        pub priority_class: Dword,
        pub scheduling_class: Dword,
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct JobObjectExtendedLimitInformation {
        pub basic_limit_information: JobObjectBasicLimitInformation,
        pub io_info: IoCounters,
        pub process_memory_limit: usize,
        pub job_memory_limit: usize,
        pub peak_process_memory_used: usize,
        pub peak_job_memory_used: usize,
    }

    #[repr(C)]
    pub struct ProcessEntry32W {
        pub dw_size: Dword,
        pub cnt_usage: Dword,
        pub th32_process_id: Dword,
        pub th32_default_heap_id: usize,
        pub th32_module_id: Dword,
        pub cnt_threads: Dword,
        pub th32_parent_process_id: Dword,
        pub pc_pri_class_base: i32,
        pub dw_flags: Dword,
        pub sz_exe_file: [u16; 260],
    }

    #[link(name = "kernel32")]
    extern "system" {
        pub fn LoadLibraryW(lp_lib_file_name: *const u16) -> HModule;
        pub fn GetProcAddress(h_module: HModule, lp_proc_name: *const c_char) -> FarProc;
        pub fn CloseHandle(h_object: Handle) -> Bool;
        pub fn CreateJobObjectW(lp_job_attributes: *mut c_void, lp_name: *const u16) -> Handle;
        pub fn SetInformationJobObject(
            h_job: Handle,
            job_object_info_class: c_int,
            lp_job_object_info: *const c_void,
            cb_job_object_info_length: Dword,
        ) -> Bool;
        pub fn AssignProcessToJobObject(h_job: Handle, h_process: Handle) -> Bool;
        pub fn TerminateJobObject(h_job: Handle, u_exit_code: u32) -> Bool;
        pub fn CreateToolhelp32Snapshot(dw_flags: Dword, th32_process_id: Dword) -> Handle;
        pub fn Process32FirstW(h_snapshot: Handle, lppe: *mut ProcessEntry32W) -> Bool;
        pub fn Process32NextW(h_snapshot: Handle, lppe: *mut ProcessEntry32W) -> Bool;
        pub fn OpenProcess(dw_desired_access: Dword, b_inherit_handle: Bool, dw_process_id: Dword) -> Handle;
        pub fn TerminateProcess(h_process: Handle, u_exit_code: u32) -> Bool;
        pub fn GetFileAttributesW(lp_file_name: *const u16) -> Dword;
        pub fn RemoveDirectoryW(lp_path_name: *const u16) -> Bool;
        pub fn TzSpecificLocalTimeToSystemTime(
            lp_time_zone_information: *const c_void,
            lp_local_time: *const WinSystemTime,
            lp_universal_time: *mut WinSystemTime,
        ) -> Bool;
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct WinSystemTime {
        pub w_year: u16,
        pub w_month: u16,
        pub w_day_of_week: u16,
        pub w_day: u16,
        pub w_hour: u16,
        pub w_minute: u16,
        pub w_second: u16,
        pub w_milliseconds: u16,
    }

    pub fn local_civil_to_utc(
        year: i64,
        month: u32,
        day: u32,
        hour: i64,
        min: i64,
        sec: i64,
    ) -> Option<(i64, u32, u32, i64, i64, i64)> {
        if !(1601..=30827).contains(&year) {
            return None;
        }
        let local = WinSystemTime {
            w_year: year as u16,
            w_month: month as u16,
            w_day_of_week: 0,
            w_day: day as u16,
            w_hour: hour as u16,
            w_minute: min as u16,
            w_second: sec.min(59) as u16,
            w_milliseconds: 0,
        };
        let mut utc = WinSystemTime::default();
        // SAFETY: NULL time-zone pointer instructs Win32 to convert using the active system local time zone.
        let ok = unsafe { TzSpecificLocalTimeToSystemTime(ptr::null(), &local, &mut utc) };
        if ok == 0 {
            return None;
        }
        Some((
            utc.w_year as i64,
            utc.w_month as u32,
            utc.w_day as u32,
            utc.w_hour as i64,
            utc.w_minute as i64,
            (utc.w_second as i64) + if sec == 60 { 1 } else { 0 },
        ))
    }

    pub fn to_wide(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub struct KillJobGuard(pub Handle);

    impl Drop for KillJobGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: Closing a KILL_ON_JOB_CLOSE job handle is always valid when non-null.
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    pub fn create_kill_job_and_attach(proc_handle: Handle, root_pid: u32) -> Option<KillJobGuard> {
        // SAFETY: Win32 Job Object creation + KILL_ON_JOB_CLOSE setup + descendant attachment.
        unsafe {
            let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info = JobObjectExtendedLimitInformation::default();
            info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                &info as *const _ as *const c_void,
                std::mem::size_of::<JobObjectExtendedLimitInformation>() as Dword,
            );
            if ok == 0 {
                CloseHandle(job);
                return None;
            }
            let _ = AssignProcessToJobObject(job, proc_handle);
            for pid in collect_descendant_pids(root_pid) {
                let hp = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_QUOTA, 0, pid);
                if !hp.is_null() {
                    let _ = AssignProcessToJobObject(job, hp);
                    CloseHandle(hp);
                }
            }
            Some(KillJobGuard(job))
        }
    }

    pub fn collect_descendant_pids(root_pid: u32) -> Vec<u32> {
        // SAFETY: Standard CreateToolhelp32Snapshot process table walk.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap.is_null() || snap == INVALID_HANDLE_VALUE {
                return Vec::new();
            }
            let mut edges: Vec<(u32, u32)> = Vec::new();
            let mut entry: ProcessEntry32W = std::mem::zeroed();
            entry.dw_size = std::mem::size_of::<ProcessEntry32W>() as Dword;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    edges.push((entry.th32_parent_process_id, entry.th32_process_id));
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);

            let mut seen: HashSet<u32> = HashSet::new();
            let mut frontier: Vec<u32> = vec![root_pid];
            let mut out: Vec<u32> = Vec::new();
            while let Some(cur) = frontier.pop() {
                for &(ppid, pid) in &edges {
                    if ppid == cur && pid != root_pid && seen.insert(pid) {
                        out.push(pid);
                        frontier.push(pid);
                    }
                }
            }
            out
        }
    }

    pub fn terminate_tree(job: Option<&KillJobGuard>, root_pid: u32) {
        // SAFETY: Terminate all descendants via Toolhelp32 and Job Object.
        unsafe {
            for pid in collect_descendant_pids(root_pid) {
                let hp = OpenProcess(PROCESS_TERMINATE, 0, pid);
                if !hp.is_null() {
                    let _ = TerminateProcess(hp, 1);
                    CloseHandle(hp);
                }
            }
            if let Some(jg) = job {
                if !jg.0.is_null() {
                    let _ = TerminateJobObject(jg.0, 1);
                }
            }
        }
    }
}

pub fn is_link_or_junction(path: &Path) -> bool {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return true;
        }
    }
    #[cfg(windows)]
    {
        let wide = win_ffi::to_wide(&path.to_string_lossy());
        // SAFETY: GetFileAttributesW reads NTFS attributes on NUL-terminated UTF-16 path.
        let attrs = unsafe { win_ffi::GetFileAttributesW(wide.as_ptr()) };
        if attrs != win_ffi::INVALID_FILE_ATTRIBUTES && (attrs & win_ffi::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

pub fn remove_junction_dir(path: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let wide = win_ffi::to_wide(&path.to_string_lossy());
        // SAFETY: RemoveDirectoryW detaches NTFS junction/reparse point without deleting target contents.
        let ok = unsafe { win_ffi::RemoveDirectoryW(wide.as_ptr()) };
        if ok != 0 {
            return Ok(());
        }
    }
    fs::remove_dir(path).map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct CmdResult {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

impl CmdResult {
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub fn run_command_with_job(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    env_overrides: &[(&str, &str)],
    stdin_bytes: Option<&[u8]>,
    timeout_ms: Option<u64>,
) -> Result<CmdResult, String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if stdin_bytes.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    if let Some(dir) = cwd {
        if dir.is_dir() {
            cmd.current_dir(dir);
        }
    }
    for &(k, v) in env_overrides {
        cmd.env(k, v);
    }
    #[cfg(windows)]
    {
        cmd.creation_flags(win_ffi::CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {}", program, e))?;
    let root_pid = child.id();

    #[cfg(windows)]
    let mut job_guard = {
        let raw_h = child.as_raw_handle() as win_ffi::Handle;
        win_ffi::create_kill_job_and_attach(raw_h, root_pid)
    };

    if let Some(input) = stdin_bytes {
        if let Some(mut child_in) = child.stdin.take() {
            let data = input.to_vec();
            thread::spawn(move || {
                let _ = child_in.write_all(&data);
            });
        }
    }

    let out_pipe = child.stdout.take();
    let err_pipe = child.stderr.take();
    let out_shared = Arc::new(Mutex::new(Vec::<u8>::new()));
    let err_shared = Arc::new(Mutex::new(Vec::<u8>::new()));
    let out_writer = Arc::clone(&out_shared);
    let err_writer = Arc::clone(&err_shared);
    let (tx_out, rx_out) = mpsc::channel::<()>();
    let (tx_err, rx_err) = mpsc::channel::<()>();

    thread::spawn(move || {
        if let Some(mut p) = out_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = p.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut g) = out_writer.lock() {
                    g.extend_from_slice(&chunk[..n]);
                }
            }
        }
        let _ = tx_out.send(());
    });
    thread::spawn(move || {
        if let Some(mut p) = err_pipe {
            let mut chunk = [0u8; 4096];
            while let Ok(n) = p.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                if let Ok(mut g) = err_writer.lock() {
                    g.extend_from_slice(&chunk[..n]);
                }
            }
        }
        let _ = tx_err.send(());
    });

    let start = Instant::now();
    let deadline = timeout_ms.map(|ms| start + Duration::from_millis(ms));
    let mut timed_out = false;
    let mut exit_code: i32;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(1);
                break;
            }
            Ok(None) => {
                if let Some(dl) = deadline {
                    if Instant::now() >= dl {
                        timed_out = true;
                        #[cfg(windows)]
                        {
                            win_ffi::terminate_tree(job_guard.as_ref(), root_pid);
                            drop(job_guard.take());
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        exit_code = 124;
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(8));
            }
            Err(e) => {
                #[cfg(windows)]
                {
                    win_ffi::terminate_tree(job_guard.as_ref(), root_pid);
                    drop(job_guard.take());
                }
                let _ = child.kill();
                return Err(format!("wait {}: {}", program, e));
            }
        }
    }

    // SAFETY: Enforce the overall command deadline across stdout/stderr pipe EOF as well so a surviving grandchild inheriting pipes cannot hang after root exits.
    if timed_out {
        let _ = rx_out.recv_timeout(Duration::from_millis(150));
        let _ = rx_err.recv_timeout(Duration::from_millis(150));
    } else if let Some(dl) = deadline {
        for rx in [&rx_out, &rx_err] {
            let now = Instant::now();
            let rem = if dl > now { dl - now } else { Duration::ZERO };
            if rx.recv_timeout(rem).is_err() {
                timed_out = true;
                exit_code = 124;
                #[cfg(windows)]
                {
                    win_ffi::terminate_tree(job_guard.as_ref(), root_pid);
                    drop(job_guard.take());
                }
                let _ = rx_out.recv_timeout(Duration::from_millis(150));
                let _ = rx_err.recv_timeout(Duration::from_millis(150));
                break;
            }
        }
    } else {
        let _ = rx_out.recv();
        let _ = rx_err.recv();
    }

    #[cfg(windows)]
    drop(job_guard);

    let stdout = std::mem::take(&mut *out_shared.lock().unwrap_or_else(|e| e.into_inner()));
    let stderr = std::mem::take(&mut *err_shared.lock().unwrap_or_else(|e| e.into_inner()));

    Ok(CmdResult {
        code: exit_code,
        stdout,
        stderr,
        timed_out,
    })
}

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
pub const SQLITE_OPEN_READONLY: c_int = 0x00000001;
pub const SQLITE_OPEN_READWRITE: c_int = 0x00000002;
pub const SQLITE_OPEN_CREATE: c_int = 0x00000004;
const SQLITE_TRANSIENT: isize = -1;

type SqliteDb = *mut c_void;
type SqliteStmt = *mut c_void;

struct SqliteApi {
    open_v2: unsafe extern "C" fn(*const c_char, *mut SqliteDb, c_int, *const c_char) -> c_int,
    close_v2: unsafe extern "C" fn(SqliteDb) -> c_int,
    exec: unsafe extern "C" fn(SqliteDb, *const c_char, *const c_void, *mut c_void, *mut *mut c_char) -> c_int,
    busy_timeout: unsafe extern "C" fn(SqliteDb, c_int) -> c_int,
    prepare_v2: unsafe extern "C" fn(SqliteDb, *const c_char, c_int, *mut SqliteStmt, *mut *const c_char) -> c_int,
    step: unsafe extern "C" fn(SqliteStmt) -> c_int,
    finalize: unsafe extern "C" fn(SqliteStmt) -> c_int,
    column_count: unsafe extern "C" fn(SqliteStmt) -> c_int,
    column_type: unsafe extern "C" fn(SqliteStmt, c_int) -> c_int,
    column_bytes: unsafe extern "C" fn(SqliteStmt, c_int) -> c_int,
    column_text: unsafe extern "C" fn(SqliteStmt, c_int) -> *const c_char,
    column_blob: unsafe extern "C" fn(SqliteStmt, c_int) -> *const c_void,
    column_int64: unsafe extern "C" fn(SqliteStmt, c_int) -> i64,
    column_double: unsafe extern "C" fn(SqliteStmt, c_int) -> c_double,
    bind_text: unsafe extern "C" fn(SqliteStmt, c_int, *const c_char, c_int, isize) -> c_int,
    bind_blob: unsafe extern "C" fn(SqliteStmt, c_int, *const c_void, c_int, isize) -> c_int,
    bind_int64: unsafe extern "C" fn(SqliteStmt, c_int, i64) -> c_int,
    bind_double: unsafe extern "C" fn(SqliteStmt, c_int, c_double) -> c_int,
    bind_null: unsafe extern "C" fn(SqliteStmt, c_int) -> c_int,
    errmsg: unsafe extern "C" fn(SqliteDb) -> *const c_char,
    changes: unsafe extern "C" fn(SqliteDb) -> c_int,
}

unsafe impl Send for SqliteApi {}
unsafe impl Sync for SqliteApi {}

static SQLITE_API: OnceLock<Result<SqliteApi, String>> = OnceLock::new();

fn home_dir_opt() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

#[cfg(windows)]
fn load_sqlite_api_impl() -> Result<SqliteApi, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for env_k in ["CARBON_SQLITE_DLL", "CHAT_BUS_SQLITE_DLL"] {
        if let Ok(ov) = env::var(env_k) {
            let t = ov.trim();
            if !t.is_empty() {
                candidates.push(PathBuf::from(t));
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("sqlite3.dll"));
        }
    }
    if let Some(home) = home_dir_opt() {
        candidates.push(
            home.join(".gemini")
                .join("config")
                .join("plugins")
                .join("chat-bus")
                .join("bin")
                .join("sqlite3.dll"),
        );
        for py in ["Python312", "Python311", "Python313"] {
            candidates.push(
                home.join("AppData")
                    .join("Local")
                    .join("Programs")
                    .join("Python")
                    .join(py)
                    .join("DLLs")
                    .join("sqlite3.dll"),
            );
        }
    }
    candidates.push(PathBuf::from("sqlite3.dll"));

    let mut hmod: win_ffi::HModule = ptr::null_mut();
    for cand in candidates {
        let wide = win_ffi::to_wide(&cand.to_string_lossy());
        // SAFETY: LoadLibraryW loads a NUL-terminated UTF-16 DLL path.
        let h = unsafe { win_ffi::LoadLibraryW(wide.as_ptr()) };
        if !h.is_null() {
            hmod = h;
            break;
        }
    }
    if hmod.is_null() {
        return Err("sqlite3.dll not found".to_string());
    }

    unsafe fn sym<T>(hmod: win_ffi::HModule, name: &[u8]) -> Result<T, String> {
        let p = win_ffi::GetProcAddress(hmod, name.as_ptr() as *const c_char);
        if p.is_null() {
            return Err(format!(
                "Missing sqlite3 symbol {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            ));
        }
        Ok(std::mem::transmute_copy(&p))
    }

    // SAFETY: Resolve SQLite C ABI symbols and invoke sqlite3_initialize() first (SQLITE_OMIT_AUTOINIT safe).
    unsafe {
        let init_fn: unsafe extern "C" fn() -> c_int = sym(hmod, b"sqlite3_initialize\0")?;
        let rc = init_fn();
        if rc != SQLITE_OK {
            return Err(format!("sqlite3_initialize failed rc={}", rc));
        }
        Ok(SqliteApi {
            open_v2: sym(hmod, b"sqlite3_open_v2\0")?,
            close_v2: sym(hmod, b"sqlite3_close_v2\0")?,
            exec: sym(hmod, b"sqlite3_exec\0")?,
            busy_timeout: sym(hmod, b"sqlite3_busy_timeout\0")?,
            prepare_v2: sym(hmod, b"sqlite3_prepare_v2\0")?,
            step: sym(hmod, b"sqlite3_step\0")?,
            finalize: sym(hmod, b"sqlite3_finalize\0")?,
            column_count: sym(hmod, b"sqlite3_column_count\0")?,
            column_type: sym(hmod, b"sqlite3_column_type\0")?,
            column_bytes: sym(hmod, b"sqlite3_column_bytes\0")?,
            column_text: sym(hmod, b"sqlite3_column_text\0")?,
            column_blob: sym(hmod, b"sqlite3_column_blob\0")?,
            column_int64: sym(hmod, b"sqlite3_column_int64\0")?,
            column_double: sym(hmod, b"sqlite3_column_double\0")?,
            bind_text: sym(hmod, b"sqlite3_bind_text\0")?,
            bind_blob: sym(hmod, b"sqlite3_bind_blob\0")?,
            bind_int64: sym(hmod, b"sqlite3_bind_int64\0")?,
            bind_double: sym(hmod, b"sqlite3_bind_double\0")?,
            bind_null: sym(hmod, b"sqlite3_bind_null\0")?,
            errmsg: sym(hmod, b"sqlite3_errmsg\0")?,
            changes: sym(hmod, b"sqlite3_changes\0")?,
        })
    }
}

#[cfg(not(windows))]
fn load_sqlite_api_impl() -> Result<SqliteApi, String> {
    Err("Dynamic sqlite3.dll loader is Windows-specific".to_string())
}

fn sqlite_api() -> Result<&'static SqliteApi, String> {
    match SQLITE_API.get_or_init(load_sqlite_api_impl) {
        Ok(api) => Ok(api),
        Err(e) => Err(e.clone()),
    }
}

#[derive(Debug, Clone)]
pub enum SqlParam {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
pub enum SqlVal {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl SqlVal {
    pub fn as_str(&self) -> String {
        match self {
            SqlVal::Null => String::new(),
            SqlVal::Int(v) => v.to_string(),
            SqlVal::Float(v) => v.to_string(),
            SqlVal::Text(s) => s.clone(),
            SqlVal::Blob(b) => String::from_utf8_lossy(b).into_owned(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            SqlVal::Blob(b) => b.as_slice(),
            SqlVal::Text(s) => s.as_bytes(),
            _ => &[],
        }
    }

    pub fn as_i64(&self) -> i64 {
        match self {
            SqlVal::Int(v) => *v,
            SqlVal::Float(v) => *v as i64,
            SqlVal::Text(s) => s.parse().unwrap_or(0),
            SqlVal::Blob(b) => std::str::from_utf8(b).ok().and_then(|s| s.parse().ok()).unwrap_or(0),
            SqlVal::Null => 0,
        }
    }

    pub fn as_f64(&self) -> f64 {
        match self {
            SqlVal::Float(v) => *v,
            SqlVal::Int(v) => *v as f64,
            SqlVal::Text(s) => s.parse().unwrap_or(0.0),
            SqlVal::Blob(b) => std::str::from_utf8(b).ok().and_then(|s| s.parse().ok()).unwrap_or(0.0),
            SqlVal::Null => 0.0,
        }
    }
}

pub struct SqliteConn {
    api: &'static SqliteApi,
    db: SqliteDb,
}

impl SqliteConn {
    pub fn open(path: &Path, flags: c_int) -> Result<Self, String> {
        let api = sqlite_api()?;
        if (flags & SQLITE_OPEN_CREATE) != 0 {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let c_path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| "invalid NUL in db path".to_string())?;
        let mut db: SqliteDb = ptr::null_mut();
        // SAFETY: sqlite3_open_v2 initializes `db` handle; closed on error or Drop.
        unsafe {
            let rc = (api.open_v2)(c_path.as_ptr(), &mut db, flags, ptr::null());
            if rc != SQLITE_OK || db.is_null() {
                let msg = if !db.is_null() {
                    let p = (api.errmsg)(db);
                    let s = if p.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(p).to_string_lossy().into_owned()
                    };
                    (api.close_v2)(db);
                    s
                } else {
                    format!("rc={}", rc)
                };
                return Err(format!("sqlite3_open_v2 failed: {}", msg));
            }
            (api.busy_timeout)(db, 5000);
        }
        Ok(Self { api, db })
    }

    fn last_error(&self) -> String {
        // SAFETY: `self.db` is valid for lifetime of `SqliteConn`.
        unsafe {
            let p = (self.api.errmsg)(self.db);
            if p.is_null() {
                "sqlite error".to_string()
            } else {
                CStr::from_ptr(p).to_string_lossy().into_owned()
            }
        }
    }

    pub fn set_busy_timeout(&self, ms: i32) {
        // SAFETY: `self.db` is valid for lifetime of `SqliteConn`.
        unsafe {
            (self.api.busy_timeout)(self.db, ms as c_int);
        }
    }

    pub fn exec_batch(&self, sql: &str) -> Result<(), String> {
        let c_sql = CString::new(sql.as_bytes()).map_err(|_| "invalid NUL in SQL".to_string())?;
        // SAFETY: `sqlite3_exec` runs batch SQL without callback.
        unsafe {
            let rc = (self.api.exec)(self.db, c_sql.as_ptr(), ptr::null(), ptr::null_mut(), ptr::null_mut());
            if rc != SQLITE_OK {
                return Err(self.last_error());
            }
        }
        Ok(())
    }

    pub fn execute(&self, sql: &str, params: &[SqlParam]) -> Result<i32, String> {
        let _ = self.query(sql, params)?;
        // SAFETY: `sqlite3_changes` returns rows modified on `self.db`.
        let chg = unsafe { (self.api.changes)(self.db) };
        Ok(chg as i32)
    }

    pub fn query(&self, sql: &str, params: &[SqlParam]) -> Result<Vec<Vec<SqlVal>>, String> {
        let c_sql = CString::new(sql.as_bytes()).map_err(|_| "invalid NUL in SQL".to_string())?;
        let mut stmt: SqliteStmt = ptr::null_mut();
        // SAFETY: Prepare, bind parameters with SQLITE_TRANSIENT, step all rows, and always finalize.
        unsafe {
            let rc = (self.api.prepare_v2)(self.db, c_sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
            if rc != SQLITE_OK || stmt.is_null() {
                return Err(self.last_error());
            }
            for (idx, param) in params.iter().enumerate() {
                let pos = (idx + 1) as c_int;
                let brc = match param {
                    SqlParam::Null => (self.api.bind_null)(stmt, pos),
                    SqlParam::Int(v) => (self.api.bind_int64)(stmt, pos, *v),
                    SqlParam::Float(v) => (self.api.bind_double)(stmt, pos, *v),
                    SqlParam::Text(s) => (self.api.bind_text)(
                        stmt,
                        pos,
                        if s.is_empty() { b"\0".as_ptr() as *const c_char } else { s.as_ptr() as *const c_char },
                        s.len() as c_int,
                        SQLITE_TRANSIENT,
                    ),
                    SqlParam::Blob(b) => (self.api.bind_blob)(
                        stmt,
                        pos,
                        if b.is_empty() { b"\0".as_ptr() as *const c_void } else { b.as_ptr() as *const c_void },
                        b.len() as c_int,
                        SQLITE_TRANSIENT,
                    ),
                };
                if brc != SQLITE_OK {
                    let err = self.last_error();
                    (self.api.finalize)(stmt);
                    return Err(err);
                }
            }
            let col_n = (self.api.column_count)(stmt);
            let mut rows = Vec::new();
            loop {
                let src = (self.api.step)(stmt);
                if src == SQLITE_ROW {
                    let mut row = Vec::with_capacity(col_n as usize);
                    for c in 0..col_n {
                        let ctype = (self.api.column_type)(stmt, c);
                        // INVARIANT: SQLite column types: 1=INTEGER, 2=FLOAT, 3=TEXT, 4=BLOB, 5=NULL.
                        let val = match ctype {
                            1 => SqlVal::Int((self.api.column_int64)(stmt, c)),
                            2 => SqlVal::Float((self.api.column_double)(stmt, c)),
                            4 => {
                                let p = (self.api.column_blob)(stmt, c);
                                let n = (self.api.column_bytes)(stmt, c);
                                if p.is_null() || n <= 0 {
                                    SqlVal::Blob(Vec::new())
                                } else {
                                    let sl = std::slice::from_raw_parts(p as *const u8, n as usize);
                                    SqlVal::Blob(sl.to_vec())
                                }
                            }
                            5 => SqlVal::Null,
                            _ => {
                                let p = (self.api.column_text)(stmt, c);
                                let n = (self.api.column_bytes)(stmt, c);
                                if p.is_null() || n <= 0 {
                                    SqlVal::Text(String::new())
                                } else {
                                    let sl = std::slice::from_raw_parts(p as *const u8, n as usize);
                                    SqlVal::Text(String::from_utf8_lossy(sl).into_owned())
                                }
                            }
                        };
                        row.push(val);
                    }
                    rows.push(row);
                } else if src == SQLITE_DONE {
                    break;
                } else {
                    let err = self.last_error();
                    (self.api.finalize)(stmt);
                    return Err(err);
                }
            }
            (self.api.finalize)(stmt);
            Ok(rows)
        }
    }
}

impl Drop for SqliteConn {
    fn drop(&mut self) {
        if !self.db.is_null() {
            // SAFETY: Close valid SQLite connection once in Drop.
            unsafe {
                (self.api.close_v2)(self.db);
            }
            self.db = ptr::null_mut();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iso_roundtrip_and_offsets() {
        let ts = parse_iso_ts("2026-11-17T13:30:43Z");
        assert_eq!(format_iso_utc(ts), "2026-11-17T13:30:43Z");
        let ts_plus5 = parse_iso_ts("2026-11-17T18:30:43+05:00");
        assert!((ts - ts_plus5).abs() < 1e-6);
        let ts_frac = parse_iso_ts("2026-11-17T13:30:43.500Z");
        assert!((ts_frac - ts - 0.5).abs() < 1e-6);
        assert_eq!(parse_iso_ts("2026-11-17T€:00:00Z"), 0.0);
        assert_eq!(parse_iso_ts("2026-11-17T13:30:43+0€0"), 0.0);
    }

    #[test]
    fn test_sqlite_memory_and_job_runner() {
        let conn = SqliteConn::open(Path::new(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE).unwrap();
        conn.exec_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);").unwrap();
        conn.execute("INSERT INTO t (name) VALUES (?)", &[SqlParam::Text("carbon".to_string())]).unwrap();
        let rows = conn.query("SELECT id, name FROM t", &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][1].as_str(), "carbon");

        let res = run_command_with_job("git", &["--version".to_string()], None, &[], None, Some(5000)).unwrap();
        assert_eq!(res.code, 0);
        assert!(res.stdout_str().to_lowercase().contains("git"));
    }

    #[test]
    fn test_timeout_enforced_when_grandchild_holds_stdout_after_root_exit() {
        let t0 = Instant::now();
        #[cfg(windows)]
        let res = run_command_with_job(
            "cmd",
            &[
                "/C".to_string(),
                "echo started & start /B ping -n 15 127.0.0.1".to_string(),
            ],
            None,
            &[],
            None,
            Some(300),
        )
        .unwrap();
        #[cfg(not(windows))]
        let res = run_command_with_job(
            "sh",
            &["-c".to_string(), "echo started; sleep 10 &".to_string()],
            None,
            &[],
            None,
            Some(300),
        )
        .unwrap();
        assert!(res.timed_out);
        assert_eq!(res.code, 124);
        assert!(t0.elapsed() < Duration::from_secs(3));
        assert!(res.stdout_str().contains("started"));
    }
}
