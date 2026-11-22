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
use std::collections::HashSet;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(test)]
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
        pub fn GetExitCodeProcess(h_process: Handle, lp_exit_code: *mut Dword) -> Bool;
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

    // INVARIANT: Enforce the overall command deadline across stdout/stderr pipe EOF as well so a surviving grandchild inheriting pipes cannot hang after root exits.
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
    errmsg: unsafe extern "C" fn(SqliteDb) -> *const c_char,
    changes: unsafe extern "C" fn(SqliteDb) -> c_int,
}

// SAFETY: `SqliteApi` holds immutable C ABI function pointers backed by a process-lifetime loaded SQLite shared library handle that is never unloaded.
unsafe impl Send for SqliteApi {}
// SAFETY: Concurrent callers invoke thread-safe SQLite C entrypoints on distinct `sqlite3*` handles through immutable function pointers.
unsafe impl Sync for SqliteApi {}

static SQLITE_API: OnceLock<Result<SqliteApi, String>> = OnceLock::new();

fn home_dir_opt() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .or_else(|| env::var_os("HOME"))
        .map(PathBuf::from)
}

fn bind_sqlite_symbols(
    resolve: impl Fn(&[u8]) -> Result<*const c_void, String>,
) -> Result<SqliteApi, String> {
    // SAFETY: Caller instantiates `T` exclusively as `unsafe extern "C" fn(...)` matching the exact SQLite C ABI signature of `name` (pointer-sized on all supported targets).
    unsafe fn cast_sym<T>(
        resolve: &impl Fn(&[u8]) -> Result<*const c_void, String>,
        name: &[u8],
    ) -> Result<T, String> {
        let p = resolve(name)?;
        // SAFETY: `p` is a non-null symbol address returned by `GetProcAddress`/`dlsym` and `T` is a pointer-sized `extern "C"` fn pointer.
        Ok(unsafe { std::mem::transmute_copy(&p) })
    }

    // SAFETY: Resolve SQLite C ABI symbols and invoke sqlite3_initialize() first (SQLITE_OMIT_AUTOINIT safe).
    unsafe {
        let init_fn: unsafe extern "C" fn() -> c_int = cast_sym(&resolve, b"sqlite3_initialize\0")?;
        let rc = init_fn();
        if rc != SQLITE_OK {
            return Err(format!("sqlite3_initialize failed rc={}", rc));
        }
        Ok(SqliteApi {
            open_v2: cast_sym(&resolve, b"sqlite3_open_v2\0")?,
            close_v2: cast_sym(&resolve, b"sqlite3_close_v2\0")?,
            exec: cast_sym(&resolve, b"sqlite3_exec\0")?,
            busy_timeout: cast_sym(&resolve, b"sqlite3_busy_timeout\0")?,
            prepare_v2: cast_sym(&resolve, b"sqlite3_prepare_v2\0")?,
            step: cast_sym(&resolve, b"sqlite3_step\0")?,
            finalize: cast_sym(&resolve, b"sqlite3_finalize\0")?,
            column_count: cast_sym(&resolve, b"sqlite3_column_count\0")?,
            column_type: cast_sym(&resolve, b"sqlite3_column_type\0")?,
            column_bytes: cast_sym(&resolve, b"sqlite3_column_bytes\0")?,
            column_text: cast_sym(&resolve, b"sqlite3_column_text\0")?,
            column_blob: cast_sym(&resolve, b"sqlite3_column_blob\0")?,
            column_int64: cast_sym(&resolve, b"sqlite3_column_int64\0")?,
            column_double: cast_sym(&resolve, b"sqlite3_column_double\0")?,
            bind_text: cast_sym(&resolve, b"sqlite3_bind_text\0")?,
            bind_blob: cast_sym(&resolve, b"sqlite3_bind_blob\0")?,
            bind_int64: cast_sym(&resolve, b"sqlite3_bind_int64\0")?,
            bind_double: cast_sym(&resolve, b"sqlite3_bind_double\0")?,
            errmsg: cast_sym(&resolve, b"sqlite3_errmsg\0")?,
            changes: cast_sym(&resolve, b"sqlite3_changes\0")?,
        })
    }
}

#[cfg(windows)]
fn load_sqlite_api_impl() -> Result<SqliteApi, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for env_k in ["CARBON_SQLITE_LIB", "CARBON_SQLITE_DLL", "CHAT_BUS_SQLITE_DLL"] {
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

    bind_sqlite_symbols(|name| {
        // SAFETY: `hmod` is a valid loaded module handle and `name` is NUL-terminated ASCII.
        let p = unsafe { win_ffi::GetProcAddress(hmod, name.as_ptr() as *const c_char) };
        if p.is_null() {
            return Err(format!(
                "Missing sqlite3 symbol {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            ));
        }
        Ok(p)
    })
}

#[cfg(not(windows))]
fn load_sqlite_api_impl() -> Result<SqliteApi, String> {
    const RTLD_LAZY: c_int = 1;
    #[cfg_attr(target_os = "linux", link(name = "dl"))]
    extern "C" {
        fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    }

    let mut candidates: Vec<String> = Vec::new();
    for env_k in ["CARBON_SQLITE_LIB", "CARBON_SQLITE_DLL", "CHAT_BUS_SQLITE_DLL"] {
        if let Ok(ov) = env::var(env_k) {
            let t = ov.trim();
            if !t.is_empty() {
                candidates.push(t.to_string());
            }
        }
    }
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            for leaf in ["libsqlite3.dylib", "libsqlite3.so.0", "libsqlite3.so"] {
                candidates.push(dir.join(leaf).to_string_lossy().into_owned());
            }
        }
    }
    for sys_lib in [
        "libsqlite3.dylib",
        "/usr/lib/libsqlite3.dylib",
        "/opt/homebrew/opt/sqlite/lib/libsqlite3.dylib",
        "/usr/local/opt/sqlite/lib/libsqlite3.dylib",
        "libsqlite3.so.0",
        "libsqlite3.so",
        "/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0",
        "/lib/aarch64-linux-gnu/libsqlite3.so.0",
        "/usr/lib/aarch64-linux-gnu/libsqlite3.so.0",
        "/usr/lib64/libsqlite3.so.0",
        "/usr/lib/libsqlite3.so.0",
        "/usr/lib/libsqlite3.so",
        "/usr/local/lib/libsqlite3.so",
    ] {
        candidates.push(sys_lib.to_string());
    }

    let mut handle: *mut c_void = ptr::null_mut();
    for cand in candidates {
        let Ok(cstr) = CString::new(cand) else {
            continue;
        };
        // SAFETY: `cstr` is a valid NUL-terminated path passed to POSIX `dlopen`.
        let h = unsafe { dlopen(cstr.as_ptr(), RTLD_LAZY) };
        if !h.is_null() {
            handle = h;
            break;
        }
    }
    if handle.is_null() {
        return Err("libsqlite3 shared library not found (install sqlite3 or set CARBON_SQLITE_LIB)".to_string());
    }

    bind_sqlite_symbols(|name| {
        // SAFETY: `handle` is a valid `dlopen` handle and `name` is NUL-terminated ASCII.
        let p = unsafe { dlsym(handle, name.as_ptr() as *const c_char) };
        if p.is_null() {
            return Err(format!(
                "Missing sqlite3 symbol {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            ));
        }
        Ok(p as *const c_void)
    })
}

fn sqlite_api() -> Result<&'static SqliteApi, String> {
    match SQLITE_API.get_or_init(load_sqlite_api_impl) {
        Ok(api) => Ok(api),
        Err(e) => Err(e.clone()),
    }
}

pub fn probe_sqlite_runtime() -> Result<(), String> {
    sqlite_api().map(|_| ())
}

#[derive(Debug, Clone)]
pub enum SqlParam {
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

pub enum LegacyLockToken {
    #[cfg(windows)]
    WinFile(fs::File),
    #[cfg(not(windows))]
    UnixDir,
}

pub enum LegacyLockReclaim {
    #[cfg(not(windows))]
    Acquired(LegacyLockToken),
    ReclaimedRetry,
    NotStale,
}

#[cfg(windows)]
pub fn delete_open_file_by_handle(file: &fs::File) -> bool {
    #[repr(C)]
    struct FileDispositionInfoEx {
        flags: u32,
    }
    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileInformationByHandle(
            hFile: *mut c_void,
            FileInformationClass: u32,
            lpFileInformation: *const c_void,
            dwBufferSize: u32,
        ) -> c_int;
    }
    let raw = file.as_raw_handle() as *mut c_void;
    let info_ex = FileDispositionInfoEx { flags: 0x0000_0003 };
    // SAFETY: `raw` is a valid open Win32 file handle with `DELETE` access; `FileDispositionInfoEx` (`21`, `DELETE | POSIX_SEMANTICS`) and fallback `FileDispositionInfo` (`4`) mark only this exact kernel `FILE_OBJECT` for unlink on handle close, never resolving by path name.
    let ok_ex = unsafe {
        SetFileInformationByHandle(
            raw,
            21,
            &info_ex as *const FileDispositionInfoEx as *const c_void,
            std::mem::size_of::<FileDispositionInfoEx>() as u32,
        )
    };
    if ok_ex != 0 {
        return true;
    }
    let info_v1 = FileDispositionInfo { delete_file: 1 };
    // SAFETY: Fallback `FileDispositionInfo` (`4`) on the same valid open file handle.
    let ok_v1 = unsafe {
        SetFileInformationByHandle(
            raw,
            4,
            &info_v1 as *const FileDispositionInfo as *const c_void,
            std::mem::size_of::<FileDispositionInfo>() as u32,
        )
    };
    ok_v1 != 0
}

#[cfg(windows)]
pub fn create_legacy_lock_exclusive(lock_path: &Path) -> std::io::Result<LegacyLockToken> {
    use std::os::windows::fs::OpenOptionsExt;
    // INVARIANT: Omit `FILE_SHARE_DELETE` (`share_mode(3)` = `READ | WRITE`) while `v2` holds the lock so a concurrent `v1` peer finishing a stale-check on `L_old` cannot `remove_file` `v2`'s newly created lock; if `v2` crashes, the OS closes the handle so stale recovery can open it with `DELETE`.
    let mut lfh = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(0xC001_0000)
        .share_mode(3)
        .create_new(true)
        .open(lock_path)?;
    let _ = writeln!(lfh, "v2 {} {}", std::process::id(), now_sec());
    let _ = lfh.flush();
    Ok(LegacyLockToken::WinFile(lfh))
}

#[cfg(not(windows))]
pub fn create_legacy_lock_exclusive(lock_path: &Path) -> std::io::Result<LegacyLockToken> {
    // INVARIANT: Migration protocol on Unix prioritizes mutual exclusion (`max_concurrent <= 1`): `v2` represents `lock_path` as an empty directory (`mkdir(2)`), so `v1` `open(O_CREAT | O_EXCL)` fails with `EEXIST` and `v1` `fs::remove_file` (`unlink(2)`) fails with `EISDIR`/`EPERM`; rolling back to `v1` via `carbon-stack install --rollback` sweeps crashed `v2` directory sentinels under `stack_home/state`.
    fs::create_dir(lock_path)?;
    Ok(LegacyLockToken::UnixDir)
}

#[cfg(windows)]
pub fn release_legacy_lock_token(_lock_path: &Path, token: LegacyLockToken) {
    let LegacyLockToken::WinFile(lfh) = token;
    let _ = delete_open_file_by_handle(&lfh);
    drop(lfh);
}

#[cfg(not(windows))]
pub fn release_legacy_lock_token(lock_path: &Path, token: LegacyLockToken) {
    let LegacyLockToken::UnixDir = token;
    // INVARIANT: `rmdir(2)` removes only an empty directory and returns `ENOTDIR` on regular files, so `v2` can never delete a `v1` regular lock file on release.
    let _ = fs::remove_dir(lock_path);
}

#[cfg(windows)]
fn path_to_wide_nul(p: &Path) -> std::io::Result<Vec<u16>> {
    let mut w: Vec<u16> = p.as_os_str().encode_wide().collect();
    if w.contains(&0) { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path")); }
    w.push(0);
    Ok(w)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn path_cstr(p: &Path) -> std::io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))
}

#[cfg(windows)]
pub(crate) fn atomic_swap_capturing_displaced(target: &Path, replacement: &Path, displaced_out: &Path) -> std::io::Result<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(lpReplacedFileName: *const u16, lpReplacementFileName: *const u16, lpBackupFileName: *const u16, dwReplaceFlags: u32, lpExclude: *mut c_void, lpReserved: *mut c_void) -> c_int;
        fn MoveFileExW(lpExistingFileName: *const u16, lpNewFileName: *const u16, dwFlags: u32) -> c_int;
    }
    let (tw, rw, dw) = (path_to_wide_nul(target)?, path_to_wide_nul(replacement)?, path_to_wide_nul(displaced_out)?);
    // SAFETY: All three buffers are NUL-terminated UTF-16 with no interior NULs; `0x6` (`IGNORE_MERGE_ERRORS | IGNORE_ACL_ERRORS`) atomically moves live `target` to `displaced_out` and puts `replacement` at `target`.
    if unsafe { ReplaceFileW(tw.as_ptr(), rw.as_ptr(), dw.as_ptr(), 0x0000_0006, ptr::null_mut(), ptr::null_mut()) } == 0 {
        let err = std::io::Error::last_os_error();
        if displaced_out.exists() {
            // SAFETY: `dwFlags = 0` omits `MOVEFILE_REPLACE_EXISTING`, so a concurrently recreated `target` is never overwritten.
            let _ = unsafe { MoveFileExW(dw.as_ptr(), tw.as_ptr(), 0) };
        }
        return Err(err);
    }
    Ok(displaced_out.to_path_buf())
}

#[cfg(target_os = "linux")]
pub(crate) fn atomic_swap_capturing_displaced(target: &Path, replacement: &Path, _displaced_out: &Path) -> std::io::Result<PathBuf> {
    extern "C" { fn renameat2(olddirfd: c_int, oldpath: *const c_char, newdirfd: c_int, newpath: *const c_char, flags: u32) -> c_int; }
    let (tc, rc_p) = (path_cstr(target)?, path_cstr(replacement)?);
    // SAFETY: NUL-terminated C paths; `RENAME_EXCHANGE` (`2`) atomically swaps `replacement` and `target` so `replacement` holds the exact displaced inode.
    if unsafe { renameat2(-100, rc_p.as_ptr(), -100, tc.as_ptr(), 2) } != 0 { return Err(std::io::Error::last_os_error()); }
    Ok(replacement.to_path_buf())
}

#[cfg(target_os = "macos")]
pub(crate) fn atomic_swap_capturing_displaced(target: &Path, replacement: &Path, _displaced_out: &Path) -> std::io::Result<PathBuf> {
    extern "C" { fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int; }
    let (tc, rc_p) = (path_cstr(target)?, path_cstr(replacement)?);
    // SAFETY: NUL-terminated C paths; `RENAME_SWAP` (`2`) atomically swaps `replacement` and `target` so `replacement` holds the exact displaced inode.
    if unsafe { renamex_np(rc_p.as_ptr(), tc.as_ptr(), 2) } != 0 { return Err(std::io::Error::last_os_error()); }
    Ok(replacement.to_path_buf())
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub(crate) fn atomic_swap_capturing_displaced(_target: &Path, _replacement: &Path, _displaced_out: &Path) -> std::io::Result<PathBuf> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "atomic file swap unsupported on this OS"))
}

#[cfg(unix)]
pub(crate) fn preserve_unix_access_or_refuse(src_target: &Path, stage_file: &fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;
    // INVARIANT: Never widen Unix access on `hooks.json` replacement: preserve original group (`fchown` when group bits are non-zero and gid differs), refuse replacing files carrying extended POSIX/macOS ACLs, and apply exact `orig_mode & 0o777`.
    let orig_meta = fs::symlink_metadata(src_target)?;
    let orig_mode = orig_meta.mode() & 0o777;
    let orig_gid = orig_meta.gid();
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn lgetxattr(path: *const c_char, name: *const c_char, value: *mut c_void, size: usize) -> isize;
            fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize) -> isize;
            fn fremovexattr(fd: c_int, name: *const c_char) -> c_int;
        }
        let tc = path_cstr(src_target)?;
        let acl_attr = b"system.posix_acl_access\0".as_ptr() as *const c_char;
        // SAFETY: Valid NUL-terminated paths and open fd; query ACL length without writing, and strip any directory-inherited ACL on `stage_file` BEFORE applying `orig_mode`.
        if unsafe { lgetxattr(tc.as_ptr(), acl_attr, ptr::null_mut(), 0) } > 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "global hooks.json has extended POSIX ACL; refusing to replace"));
        }
        if unsafe { fgetxattr(stage_file.as_raw_fd(), acl_attr, ptr::null_mut(), 0) } > 0
            && unsafe { fremovexattr(stage_file.as_raw_fd(), acl_attr) } != 0
        {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cannot strip directory-inherited POSIX ACL from staged hooks.json"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn acl_get_link_np(path: *const c_char, acl_type: c_int) -> *mut c_void;
            fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
            fn acl_free(obj_p: *mut c_void) -> c_int;
        }
        let tc = path_cstr(src_target)?;
        // SAFETY: Valid NUL-terminated path and open fd; `0x100` is `ACL_TYPE_EXTENDED` on Darwin; refuse if either source or stage carries extended ACLs.
        let acl = unsafe { acl_get_link_np(tc.as_ptr(), 0x100) };
        if !acl.is_null() {
            unsafe { acl_free(acl); }
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "global hooks.json has extended ACL; refusing to replace"));
        }
        let stage_acl = unsafe { acl_get_fd_np(stage_file.as_raw_fd(), 0x100) };
        if !stage_acl.is_null() {
            unsafe { acl_free(stage_acl); }
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "staged hooks.json inherited extended ACL; refusing to widen access"));
        }
    }
    if (orig_mode & 0o070) != 0 && stage_file.metadata()?.gid() != orig_gid {
        extern "C" { fn fchown(fd: c_int, owner: u32, group: u32) -> c_int; }
        // SAFETY: Valid open fd; `u32::MAX` (`-1`) leaves owner unchanged and sets group to `orig_gid`.
        if unsafe { fchown(stage_file.as_raw_fd(), u32::MAX, orig_gid) } != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cannot preserve original group ownership of global hooks.json"));
        }
    }
    stage_file.set_permissions(fs::Permissions::from_mode(orig_mode))
}

#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path).ok()?;
    if !m.file_type().is_file() {
        return None;
    }
    Some((m.dev(), m.ino()))
}

#[cfg(windows)]
pub fn try_reclaim_stale_legacy_lock(lock_path: &Path, stale_sec: f64) -> LegacyLockReclaim {
    use std::os::windows::fs::OpenOptionsExt;
    // INVARIANT: Open with `GENERIC_READ | DELETE` (`0x8001_0000`) and inspect content + mtime on the open `FILE_OBJECT` handle itself before marking that exact handle deleted via `SetFileInformationByHandle`, eliminating path-based `remove_file` TOCTOU races with concurrent `v1` processes.
    let mut h = match fs::OpenOptions::new()
        .read(true)
        .access_mode(0x8001_0000)
        .share_mode(7)
        .open(lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return LegacyLockReclaim::ReclaimedRetry;
        }
        Err(_) => return LegacyLockReclaim::NotStale,
    };
    let mut buf = [0u8; 96];
    let n = h.read(&mut buf).unwrap_or(0);
    let crashed_v2 = buf[..n].starts_with(b"v2 ");
    let expired_v1 = !crashed_v2
        && h.metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|mt| mt.elapsed().ok())
            .is_some_and(|age| age.as_secs_f64() > stale_sec);
    if !(crashed_v2 || expired_v1) {
        return LegacyLockReclaim::NotStale;
    }
    if delete_open_file_by_handle(&h) {
        drop(h);
        LegacyLockReclaim::ReclaimedRetry
    } else {
        LegacyLockReclaim::NotStale
    }
}

fn file_matches_exact_bytes(fh: &mut fs::File, expected: &[u8]) -> Option<fs::Metadata> {
    let meta = fh.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() != expected.len() as u64 {
        return None;
    }
    let mut buf = vec![0u8; expected.len()];
    if fh.read_exact(&mut buf).is_err() || buf.as_slice() != expected {
        return None;
    }
    Some(meta)
}

#[cfg(windows)]
pub fn remove_file_if_exact_bytes(path: &Path, expected: &[u8]) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    // INVARIANT: Open exclusively (`share_mode(0)`) with `GENERIC_READ | DELETE` (`0x8001_0000`), verify exact byte content on that open `FILE_OBJECT`, and mark that handle deleted via `delete_open_file_by_handle` so a concurrently modified file can never be unlinked.
    for attempt in 0..4u64 {
        if is_link_or_junction(path) {
            return false;
        }
        let mut h = match fs::OpenOptions::new()
            .read(true)
            .access_mode(0x8001_0000)
            .share_mode(0)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => {
                thread::sleep(Duration::from_millis(5 * (attempt + 1)));
                continue;
            }
        };
        if file_matches_exact_bytes(&mut h, expected).is_none() {
            return false;
        }
        return delete_open_file_by_handle(&h);
    }
    false
}

#[cfg(not(windows))]
pub fn remove_file_if_exact_bytes(path: &Path, expected: &[u8]) -> bool {
    if is_link_or_junction(path) {
        return false;
    }
    let Ok(mut fh) = fs::OpenOptions::new().read(true).write(true).open(path) else {
        return !path.exists();
    };
    if fh.try_lock().is_err() {
        return false;
    }
    let Some(meta) = file_matches_exact_bytes(&mut fh, expected) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file_identity(path) != Some((meta.dev(), meta.ino())) {
            return false;
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    fs::remove_file(path).is_ok()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_exchange_paths(path_a: &Path, path_b: &Path) -> std::io::Result<()> {
    let c_a = path_cstr(path_a)?;
    let c_b = path_cstr(path_b)?;
    #[cfg(target_os = "linux")]
    let rc = {
        extern "C" {
            fn renameat2(
                olddirfd: c_int,
                oldpath: *const c_char,
                newdirfd: c_int,
                newpath: *const c_char,
                flags: u32,
            ) -> c_int;
        }
        // SAFETY: `c_a` and `c_b` are valid NUL-terminated paths; `RENAME_EXCHANGE` (`2`) with `AT_FDCWD` (`-100`) atomically swaps a directory and regular file in the Linux VFS.
        unsafe { renameat2(-100, c_a.as_ptr(), -100, c_b.as_ptr(), 2) }
    };
    #[cfg(target_os = "macos")]
    let rc = {
        extern "C" {
            fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
        }
        // SAFETY: `c_a` and `c_b` are valid NUL-terminated paths; `RENAME_SWAP` (`2`) atomically swaps a directory and regular file in Darwin XNU.
        unsafe { renamex_np(c_a.as_ptr(), c_b.as_ptr(), 2) }
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub(crate) enum UnixDirReclaim {
    #[cfg(any(target_os = "linux", target_os = "macos", test))]
    AcquiredDir,
    ReclaimedRetry,
    NotStale,
}

pub(crate) fn companion_lock_path(lock_path: &Path, suffix: &str) -> PathBuf {
    match lock_path.extension() {
        Some(ext) => {
            let mut next = ext.to_os_string();
            next.push(".");
            next.push(suffix);
            lock_path.with_extension(next)
        }
        None => lock_path.with_extension(suffix),
    }
}

pub(crate) fn legacy_swap_path(lock_path: &Path) -> PathBuf {
    companion_lock_path(lock_path, "swap")
}

pub(crate) fn legacy_dir_stage_path(lock_path: &Path) -> PathBuf {
    companion_lock_path(lock_path, "dir")
}

pub(crate) fn legacy_undo_path(lock_path: &Path) -> PathBuf {
    companion_lock_path(lock_path, "undo")
}

pub(crate) fn legacy_undo_tmp_path(lock_path: &Path) -> PathBuf {
    companion_lock_path(lock_path, "undo.tmp")
}

#[cfg(unix)]
type FileSnapId = (u64, u64);
#[cfg(not(unix))]
type FileSnapId = Vec<u8>;

fn file_snap_id(p: &Path) -> Option<FileSnapId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::symlink_metadata(p).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        Some((meta.dev(), meta.ino()))
    }
    #[cfg(not(unix))]
    {
        let meta = fs::symlink_metadata(p).ok()?;
        if !meta.file_type().is_file() {
            return None;
        }
        fs::read(p).ok()
    }
}

fn encode_undo_log(ids: &[FileSnapId]) -> Vec<u8> {
    #[cfg(unix)]
    {
        let mut out = String::new();
        for (dev, ino) in ids {
            out.push_str(&format!("{} {}\n", dev, ino));
        }
        out.into_bytes()
    }
    #[cfg(not(unix))]
    {
        let mut out = Vec::new();
        for item in ids {
            let len = u32::try_from(item.len()).unwrap_or(u32::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&item[..len as usize]);
        }
        out
    }
}

fn read_undo_log(undo_path: &Path) -> Vec<FileSnapId> {
    #[cfg(unix)]
    {
        let Ok(raw) = fs::read_to_string(undo_path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in raw.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(ds), Some(is)) = (parts.next(), parts.next()) {
                if let (Ok(dev), Ok(ino)) = (ds.parse::<u64>(), is.parse::<u64>()) {
                    out.push((dev, ino));
                }
            }
        }
        out
    }
    #[cfg(not(unix))]
    {
        let Ok(raw) = fs::read(undo_path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 4 <= raw.len() {
            let len = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]) as usize;
            i += 4;
            if i + len > raw.len() {
                break;
            }
            out.push(raw[i..i + len].to_vec());
            i += len;
        }
        out
    }
}

fn write_exclusive_regular_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if is_link_or_junction(path) {
        let _ = fs::remove_file(path);
    } else if fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
    }
    let mut fh = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    fh.write_all(bytes)
}

fn write_undo_log_atomic(lock_path: &Path, ids: &[FileSnapId]) -> std::io::Result<()> {
    let undo_path = legacy_undo_path(lock_path);
    if is_link_or_junction(&undo_path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink/junction undo path",
        ));
    }
    let tmp_path = legacy_undo_tmp_path(lock_path);
    write_exclusive_regular_file(&tmp_path, &encode_undo_log(ids))?;
    if let Err(e) = fs::rename(&tmp_path, &undo_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

fn cleanup_undo_files(lock_path: &Path) {
    let _ = fs::remove_file(legacy_undo_path(lock_path));
    let _ = fs::remove_file(legacy_undo_tmp_path(lock_path));
}

fn undo_rank(ids: &[FileSnapId], target: &FileSnapId) -> usize {
    ids.iter().position(|x| x == target).unwrap_or(usize::MAX)
}

fn is_v1_slot_owner_possibly_alive(p: &Path) -> bool {
    // INVARIANT: `v1` creates `lock_path` via `O_CREAT | O_EXCL` (0 bytes) and writes `"<pid> <ts>\n"` in a separate syscall; treat a fresh slot file as exited ONLY when a complete newline-terminated header is present AND its parsed PID is confirmed dead (`!pid_is_alive(pid)`).
    let Ok(raw) = fs::read_to_string(p) else {
        return true;
    };
    if !raw.contains('\n') {
        return true;
    }
    match raw
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<u32>().ok())
    {
        Some(pid) => pid_is_alive(pid),
        None => true,
    }
}

fn pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    #[cfg(unix)]
    {
        extern "C" {
            fn kill(pid: c_int, sig: c_int) -> c_int;
        }
        let Ok(cpid) = c_int::try_from(pid) else {
            return false;
        };
        if cpid <= 0 {
            return false;
        }
        // SAFETY: `kill(cpid, 0)` sends no signal and queries POSIX kernel process existence.
        let rc = unsafe { kill(cpid, 0) };
        rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1)
    }
    #[cfg(windows)]
    {
        // SAFETY: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetExitCodeProcess` + `CloseHandle` safely queries Win32 process liveness (`STILL_ACTIVE == 259`).
        unsafe {
            let hp = win_ffi::OpenProcess(0x1000, 0, pid);
            if hp.is_null() {
                return std::io::Error::last_os_error().raw_os_error() == Some(5);
            }
            let mut code: win_ffi::Dword = 0;
            let ok = win_ffi::GetExitCodeProcess(hp, &mut code);
            win_ffi::CloseHandle(hp);
            ok != 0 && code == 259
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        false
    }
}

pub(crate) fn has_pending_unix_crash_slots(lock_path: &Path) -> bool {
    fs::symlink_metadata(legacy_swap_path(lock_path)).is_ok()
        || fs::symlink_metadata(legacy_dir_stage_path(lock_path)).is_ok()
}

fn restore_slot_to_free_lock_path(slot_path: &Path, lock_path: &Path) -> UnixDirReclaim {
    // INVARIANT: When `lock_path` is absent (e.g. removed by a delayed `unlink` of an earlier `v1` while an active `v1` lock sits in `slot_path`), restore `slot_path` via atomic `hard_link` / `create_new` without clobbering any concurrent `O_EXCL` creator.
    match fs::hard_link(slot_path, lock_path) {
        Ok(()) => {
            let _ = fs::remove_file(slot_path);
            cleanup_undo_files(lock_path);
            UnixDirReclaim::NotStale
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(slot_path);
            cleanup_undo_files(lock_path);
            UnixDirReclaim::NotStale
        }
        Err(_) => {
            if let Ok(bytes) = fs::read(slot_path) {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(lock_path)
                {
                    Ok(mut fh) => {
                        let _ = fh.write_all(&bytes);
                        let _ = fs::remove_file(slot_path);
                        cleanup_undo_files(lock_path);
                        return UnixDirReclaim::NotStale;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        let _ = fs::remove_file(slot_path);
                        cleanup_undo_files(lock_path);
                        return UnixDirReclaim::NotStale;
                    }
                    Err(_) => {}
                }
            }
            UnixDirReclaim::NotStale
        }
    }
}

pub(crate) fn is_v2_lock_artifact(p: &Path) -> bool {
    match fs::symlink_metadata(p) {
        Ok(meta) if meta.file_type().is_dir() => true,
        Ok(meta) if meta.file_type().is_file() => fs::read_to_string(p)
            .map(|s| s.starts_with("v2-probe ") || s.starts_with("v2 "))
            .unwrap_or(false),
        _ => false,
    }
}

pub(crate) fn simulated_exchange_paths(a: &Path, b: &Path, tmp: &Path) -> std::io::Result<()> {
    let _ = fs::remove_dir_all(tmp);
    let _ = fs::remove_file(tmp);
    fs::rename(a, tmp)?;
    if let Err(e) = fs::rename(b, a) {
        let _ = fs::rename(tmp, a);
        return Err(e);
    }
    fs::rename(tmp, b)
}

fn handle_missing_lock_with_slot(slot_path: &Path, lock_path: &Path) -> UnixDirReclaim {
    if is_v1_slot_owner_possibly_alive(slot_path) {
        return restore_slot_to_free_lock_path(slot_path, lock_path);
    }
    let _ = fs::remove_file(slot_path);
    cleanup_undo_files(lock_path);
    UnixDirReclaim::ReclaimedRetry
}

fn restore_displaced_v1_lock<F>(
    slot_path: &Path,
    lock_path: &Path,
    mut undo_ids: Vec<FileSnapId>,
    expected_target_id: Option<FileSnapId>,
    exchange_fn: &mut F,
) -> UnixDirReclaim
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    // INVARIANT: Persist each `placed_id` in the causal write-ahead log `<lock_path>.undo` BEFORE calling `exchange_fn` so even a crash mid-recovery (after placing dead `L_A` onto `lock_path` and moving active `L_B` into `slot_path`) preserves `undo_rank(L_B) > undo_rank(L_A)` for the next `v2` caller; if `lock_path` vanishes (`NotFound`) before `exchange_fn`, restore `slot_path` via `handle_missing_lock_with_slot` instead of deleting a live `v1` lock.
    let Some(mut placed_id) = file_snap_id(slot_path) else {
        let _ = fs::remove_file(slot_path);
        let _ = fs::remove_dir(slot_path);
        cleanup_undo_files(lock_path);
        return if lock_path.exists() {
            UnixDirReclaim::NotStale
        } else {
            UnixDirReclaim::ReclaimedRetry
        };
    };
    if !undo_ids.contains(&placed_id) {
        undo_ids.push(placed_id.clone());
    }
    if write_undo_log_atomic(lock_path, &undo_ids).is_err() {
        return UnixDirReclaim::NotStale;
    }
    match exchange_fn(slot_path, lock_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return handle_missing_lock_with_slot(slot_path, lock_path);
        }
        Err(_) => return UnixDirReclaim::NotStale,
    }
    let displaced_expected = is_v2_lock_artifact(slot_path)
        || (expected_target_id.is_some() && file_snap_id(slot_path) == expected_target_id);
    if displaced_expected {
        let _ = fs::remove_file(slot_path);
        let _ = fs::remove_dir(slot_path);
        cleanup_undo_files(lock_path);
        return UnixDirReclaim::NotStale;
    }
    for _ in 0..8 {
        match file_snap_id(lock_path) {
            None => {
                return handle_missing_lock_with_slot(slot_path, lock_path);
            }
            Some(curr_id) if curr_id != placed_id => {
                let _ = fs::remove_file(slot_path);
                cleanup_undo_files(lock_path);
                return UnixDirReclaim::NotStale;
            }
            Some(_) => {}
        }
        let Some(next_placed_id) = file_snap_id(slot_path) else {
            cleanup_undo_files(lock_path);
            return UnixDirReclaim::NotStale;
        };
        if !undo_ids.contains(&next_placed_id) {
            undo_ids.push(next_placed_id.clone());
        }
        if write_undo_log_atomic(lock_path, &undo_ids).is_err() {
            return UnixDirReclaim::NotStale;
        }
        match exchange_fn(slot_path, lock_path) {
            Ok(()) => {
                if file_snap_id(slot_path).as_ref() == Some(&placed_id) {
                    let _ = fs::remove_file(slot_path);
                    cleanup_undo_files(lock_path);
                    return UnixDirReclaim::NotStale;
                }
                placed_id = next_placed_id;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return handle_missing_lock_with_slot(slot_path, lock_path);
            }
            Err(_) => return UnixDirReclaim::NotStale,
        }
    }
    let _ = fs::remove_file(slot_path);
    cleanup_undo_files(lock_path);
    UnixDirReclaim::NotStale
}

fn is_lock_file_stale(p: &Path, stale_sec: f64) -> bool {
    is_v2_lock_artifact(p)
        || fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|mt| mt.elapsed().ok())
            .is_some_and(|age| age.as_secs_f64() > stale_sec)
}

fn reconcile_unix_slots_with_exchange<F>(
    lock_path: &Path,
    stale_sec: f64,
    exchange_fn: &mut F,
) -> Option<UnixDirReclaim>
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    let swap_path = legacy_swap_path(lock_path);
    let dir_stage = legacy_dir_stage_path(lock_path);
    let undo_path = legacy_undo_path(lock_path);
    for slot_path in [&dir_stage, &swap_path] {
        if let Ok(smeta) = fs::symlink_metadata(slot_path) {
            if smeta.file_type().is_dir() {
                let _ = fs::remove_dir(slot_path);
            } else if is_lock_file_stale(slot_path, stale_sec) {
                let _ = fs::remove_file(slot_path);
            } else {
                let undo_ids = read_undo_log(&undo_path);
                if !lock_path.exists() {
                    return Some(handle_missing_lock_with_slot(slot_path, lock_path));
                }
                if is_v2_lock_artifact(lock_path) {
                    return Some(restore_displaced_v1_lock(
                        slot_path,
                        lock_path,
                        undo_ids,
                        None,
                        exchange_fn,
                    ));
                }
                let lock_id = file_snap_id(lock_path);
                let slot_id = file_snap_id(slot_path);
                let slot_outranks_lock = match (&slot_id, &lock_id) {
                    (Some(s_id), Some(l_id)) => {
                        undo_rank(&undo_ids, s_id) > undo_rank(&undo_ids, l_id)
                    }
                    _ => false,
                };
                if is_lock_file_stale(lock_path, stale_sec) || slot_outranks_lock {
                    return Some(restore_displaced_v1_lock(
                        slot_path,
                        lock_path,
                        undo_ids,
                        lock_id,
                        exchange_fn,
                    ));
                }
                let _ = fs::remove_file(slot_path);
                cleanup_undo_files(lock_path);
                return Some(if lock_path.exists() {
                    UnixDirReclaim::NotStale
                } else {
                    UnixDirReclaim::ReclaimedRetry
                });
            }
        }
    }
    cleanup_undo_files(lock_path);
    None
}

pub(crate) fn reconcile_unix_crash_slots(lock_path: &Path, stale_sec: f64) -> UnixDirReclaim {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut ex = atomic_exchange_paths;
        reconcile_unix_slots_with_exchange(lock_path, stale_sec, &mut ex)
            .unwrap_or(UnixDirReclaim::ReclaimedRetry)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let tmp_ex = companion_lock_path(lock_path, "slot-tmp");
        let mut ex = |a: &Path, b: &Path| simulated_exchange_paths(a, b, &tmp_ex);
        reconcile_unix_slots_with_exchange(lock_path, stale_sec, &mut ex)
            .unwrap_or(UnixDirReclaim::ReclaimedRetry)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn reclaim_unix_dir_lock_with_exchange<F>(
    lock_path: &Path,
    stale_sec: f64,
    mut exchange_fn: F,
) -> UnixDirReclaim
where
    F: FnMut(&Path, &Path) -> std::io::Result<()>,
{
    use std::sync::atomic::{AtomicU64, Ordering};
    static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);
    // INVARIANT: `<lock_path>.k` (`flock`) serializes all `v2` callers. Reconcile BOTH `<lock_path>.dir` and `<lock_path>.swap` BEFORE inspecting `lock_path` (and BEFORE `mkdir` in `rio::with_file_lock`), consulting `<lock_path>.undo` and owner PID liveness so an active `v1` lock in `.swap`/`.dir` is never bypassed even when `lock_path` was unlinked.
    if let Some(slot_res) =
        reconcile_unix_slots_with_exchange(lock_path, stale_sec, &mut exchange_fn)
    {
        return slot_res;
    }
    let swap_path = legacy_swap_path(lock_path);
    let dir_stage = legacy_dir_stage_path(lock_path);
    match fs::symlink_metadata(lock_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return UnixDirReclaim::ReclaimedRetry;
        }
        Err(_) => return UnixDirReclaim::NotStale,
        Ok(meta) if meta.file_type().is_dir() => {
            // INVARIANT: With `<lock_path>.swap` reconciled and `<lock_path>.k` held, an empty directory at `lock_path` is strictly a crashed `v2` sentinel (`rmdir` fails safely on non-empty dirs or regular files).
            return if fs::remove_dir(lock_path).is_ok() {
                UnixDirReclaim::ReclaimedRetry
            } else {
                UnixDirReclaim::NotStale
            };
        }
        Ok(_) => {}
    }
    if !is_lock_file_stale(lock_path, stale_sec) {
        return UnixDirReclaim::NotStale;
    }
    let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_tag = format!("v2-probe {} {} {}\n", std::process::id(), seq, now_sec());
    if write_exclusive_regular_file(&swap_path, probe_tag.as_bytes()).is_err() {
        return UnixDirReclaim::NotStale;
    }
    if !is_lock_file_stale(lock_path, stale_sec) {
        let _ = fs::remove_file(&swap_path);
        return UnixDirReclaim::NotStale;
    }
    match exchange_fn(&swap_path, lock_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(&swap_path);
            return UnixDirReclaim::ReclaimedRetry;
        }
        Err(_) => {
            let _ = fs::remove_file(&swap_path);
            return UnixDirReclaim::NotStale;
        }
    }
    if fs::symlink_metadata(&swap_path)
        .map(|m| m.file_type().is_dir())
        .unwrap_or(false)
    {
        let _ = fs::remove_dir(&swap_path);
    } else if is_lock_file_stale(&swap_path, stale_sec) {
        let _ = fs::remove_file(&swap_path);
    } else {
        let probe_still_at_lock = fs::read_to_string(lock_path)
            .map(|s| s == probe_tag)
            .unwrap_or(false);
        if !probe_still_at_lock {
            if lock_path.exists() {
                let _ = fs::remove_file(&swap_path);
                return UnixDirReclaim::NotStale;
            }
            return handle_missing_lock_with_slot(&swap_path, lock_path);
        }
        return restore_displaced_v1_lock(&swap_path, lock_path, Vec::new(), None, &mut exchange_fn);
    }
    // INVARIANT: Phase 2 upgrades `lock_path` from our verified `probe_tag` regular file to an empty directory so no paused `v1` can `unlink(lock_path)` during `v2`'s critical section.
    if !fs::read_to_string(lock_path)
        .map(|s| s == probe_tag)
        .unwrap_or(false)
    {
        return UnixDirReclaim::ReclaimedRetry;
    }
    if fs::create_dir(&dir_stage).is_err() {
        let _ = fs::remove_file(lock_path);
        return UnixDirReclaim::ReclaimedRetry;
    }
    match exchange_fn(&dir_stage, lock_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_dir(&dir_stage);
            return UnixDirReclaim::ReclaimedRetry;
        }
        Err(_) => {
            let _ = fs::remove_dir(&dir_stage);
            let _ = fs::remove_file(lock_path);
            return UnixDirReclaim::NotStale;
        }
    }
    let displaced_our_probe = fs::read_to_string(&dir_stage)
        .map(|s| s == probe_tag)
        .unwrap_or(false);
    if displaced_our_probe {
        let _ = fs::remove_file(&dir_stage);
        UnixDirReclaim::AcquiredDir
    } else if is_lock_file_stale(&dir_stage, stale_sec) {
        let _ = fs::remove_file(&dir_stage);
        let _ = fs::remove_dir(&dir_stage);
        UnixDirReclaim::AcquiredDir
    } else {
        restore_displaced_v1_lock(&dir_stage, lock_path, Vec::new(), None, &mut exchange_fn)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn try_reclaim_stale_legacy_lock(lock_path: &Path, stale_sec: f64) -> LegacyLockReclaim {
    match reclaim_unix_dir_lock_with_exchange(lock_path, stale_sec, atomic_exchange_paths) {
        UnixDirReclaim::AcquiredDir => LegacyLockReclaim::Acquired(LegacyLockToken::UnixDir),
        UnixDirReclaim::ReclaimedRetry => LegacyLockReclaim::ReclaimedRetry,
        UnixDirReclaim::NotStale => LegacyLockReclaim::NotStale,
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn try_reclaim_stale_legacy_lock(_lock_path: &Path, _stale_sec: f64) -> LegacyLockReclaim {
    LegacyLockReclaim::NotStale
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
