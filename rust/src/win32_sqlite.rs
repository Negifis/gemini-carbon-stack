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
    pub const PROCESS_VM_READ: Dword = 0x0010;
    pub const PROCESS_SET_QUOTA: Dword = 0x0100;
    pub const PROCESS_QUERY_INFORMATION: Dword = 0x0400;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
    pub const STILL_ACTIVE: Dword = 259;
    pub const FILE_ATTRIBUTE_REPARSE_POINT: Dword = 0x00000400;
    pub const INVALID_FILE_ATTRIBUTES: Dword = 0xFFFFFFFF;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    pub struct WinFileTime {
        pub dw_low_date_time: Dword,
        pub dw_high_date_time: Dword,
    }

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
        pub fn GetProcessTimes(
            h_process: Handle,
            lp_creation_time: *mut WinFileTime,
            lp_exit_time: *mut WinFileTime,
            lp_kernel_time: *mut WinFileTime,
            lp_user_time: *mut WinFileTime,
        ) -> Bool;
        pub fn QueryFullProcessImageNameW(
            h_process: Handle,
            dw_flags: Dword,
            lp_exe_name: *mut u16,
            lpdw_size: *mut Dword,
        ) -> Bool;
        pub fn ReadProcessMemory(
            h_process: Handle,
            lp_base_address: *const c_void,
            lp_buffer: *mut c_void,
            n_size: usize,
            lp_number_of_bytes_read: *mut usize,
        ) -> Bool;
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
    bind_null: unsafe extern "C" fn(SqliteStmt, c_int) -> c_int,
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
            bind_null: cast_sym(&resolve, b"sqlite3_bind_null\0")?,
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
    if w.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains interior NUL",
        ));
    }
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
pub fn atomic_move_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> c_int;
    }
    let src_w = path_to_wide_nul(src)?;
    let dst_w = path_to_wide_nul(dst)?;
    // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 buffers; `dwFlags = 0` omits `MOVEFILE_REPLACE_EXISTING` so the NT kernel fails atomically with `ERROR_ALREADY_EXISTS`/`ERROR_FILE_EXISTS` rather than overwriting a concurrently created `dst`.
    let ok = unsafe { MoveFileExW(src_w.as_ptr(), dst_w.as_ptr(), 0) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(80 | 183)) {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, err));
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn atomic_move_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    extern "C" {
        fn renameat2(
            olddirfd: c_int,
            oldpath: *const c_char,
            newdirfd: c_int,
            newpath: *const c_char,
            flags: u32,
        ) -> c_int;
    }
    let src_c = path_cstr(src)?;
    let dst_c = path_cstr(dst)?;
    // SAFETY: `src_c` and `dst_c` are valid NUL-terminated C strings; `RENAME_NOREPLACE` (`1`) fails atomically with `EEXIST` if `dst` already exists.
    let rc = unsafe { renameat2(-100, src_c.as_ptr(), -100, dst_c.as_ptr(), 1) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn atomic_move_noreplace(src: &Path, dst: &Path) -> std::io::Result<()> {
    extern "C" {
        fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
    }
    let src_c = path_cstr(src)?;
    let dst_c = path_cstr(dst)?;
    // SAFETY: `src_c` and `dst_c` are valid NUL-terminated C strings; `RENAME_EXCL` (`4`) fails atomically with `EEXIST` if `dst` already exists.
    let rc = unsafe { renamex_np(src_c.as_ptr(), dst_c.as_ptr(), 4) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub fn atomic_move_noreplace(_src: &Path, _dst: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic noreplace move unsupported on this OS",
    ))
}

pub fn recover_stranded_displaced_file(target: &Path, displaced_out: &Path) -> Result<(), String> {
    // INVARIANT: On `ReplaceFileW` `ERROR_UNABLE_TO_MOVE_REPLACEMENT_2` (`1177`), restore `displaced_out` onto `target` strictly via `atomic_move_noreplace` (`MoveFileExW(..., 0)` / `RENAME_NOREPLACE` / `RENAME_EXCL`) so a concurrently created `target` is NEVER overwritten, and NEVER delete `displaced_out` if `target` is still missing.
    if !displaced_out.exists() {
        return Ok(());
    }
    let mut last_err = String::new();
    for attempt in 0..5u64 {
        match atomic_move_noreplace(displaced_out, target) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(displaced_out);
                return Ok(());
            }
            Err(e) => {
                if !displaced_out.exists() && target.exists() {
                    return Ok(());
                }
                last_err = e.to_string();
                thread::sleep(Duration::from_millis(5 * (attempt + 1)));
            }
        }
    }
    if target.exists() {
        let _ = fs::remove_file(displaced_out);
        Ok(())
    } else {
        Err(format!(
            "Original file {} remains stranded at backup path {} ({})",
            target.display(),
            displaced_out.display(),
            last_err
        ))
    }
}

#[cfg(windows)]
pub fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::OpenOptionsExt;
    #[repr(C)]
    struct ByHandleFileInfo {
        dw_file_attributes: u32,
        ft_creation_time_low: u32,
        ft_creation_time_high: u32,
        ft_last_access_time_low: u32,
        ft_last_access_time_high: u32,
        ft_last_write_time_low: u32,
        ft_last_write_time_high: u32,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            hFile: *mut c_void,
            lpFileInformation: *mut ByHandleFileInfo,
        ) -> c_int;
    }
    if is_link_or_junction(path) {
        return None;
    }
    let fh = fs::OpenOptions::new().read(true).share_mode(7).open(path).ok()?;
    let mut info = ByHandleFileInfo {
        dw_file_attributes: 0,
        ft_creation_time_low: 0,
        ft_creation_time_high: 0,
        ft_last_access_time_low: 0,
        ft_last_access_time_high: 0,
        ft_last_write_time_low: 0,
        ft_last_write_time_high: 0,
        dw_volume_serial_number: 0,
        n_file_size_high: 0,
        n_file_size_low: 0,
        n_number_of_links: 0,
        n_file_index_high: 0,
        n_file_index_low: 0,
    };
    // SAFETY: `fh` is a valid open Win32 file handle and `info` is a stack-allocated `BY_HANDLE_FILE_INFORMATION` struct matching the Win32 ABI.
    let ok = unsafe { GetFileInformationByHandle(fh.as_raw_handle() as *mut c_void, &mut info) };
    if ok == 0 {
        return None;
    }
    let idx = ((info.n_file_index_high as u64) << 32) | (info.n_file_index_low as u64);
    Some((info.dw_volume_serial_number as u64, idx))
}

#[cfg(unix)]
pub fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::symlink_metadata(path).ok()?;
    if !m.file_type().is_file() {
        return None;
    }
    Some((m.dev(), m.ino()))
}

#[cfg(all(not(windows), not(unix)))]
pub fn file_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

#[cfg(windows)]
pub fn atomic_replace_capturing_displaced(
    target: &Path,
    replacement: &Path,
    displaced_out: &Path,
) -> std::io::Result<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut c_void,
            lpReserved: *mut c_void,
        ) -> c_int;
    }
    let target_w = path_to_wide_nul(target)?;
    let repl_w = path_to_wide_nul(replacement)?;
    let disp_w = path_to_wide_nul(displaced_out)?;
    // SAFETY: `target_w`, `repl_w`, and `disp_w` are valid NUL-terminated UTF-16 buffers with no interior NULs; `0x0000_0006` (`REPLACEFILE_IGNORE_MERGE_ERRORS | REPLACEFILE_IGNORE_ACL_ERRORS`) moves the live `target` into `displaced_out` and renames `replacement` onto `target`.
    let ok = unsafe {
        ReplaceFileW(
            target_w.as_ptr(),
            repl_w.as_ptr(),
            disp_w.as_ptr(),
            0x0000_0006,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        let _ = recover_stranded_displaced_file(target, displaced_out);
        return Err(err);
    }
    Ok(displaced_out.to_path_buf())
}

#[cfg(target_os = "linux")]
pub fn atomic_replace_capturing_displaced(
    target: &Path,
    replacement: &Path,
    _displaced_out: &Path,
) -> std::io::Result<PathBuf> {
    extern "C" {
        fn renameat2(
            olddirfd: c_int,
            oldpath: *const c_char,
            newdirfd: c_int,
            newpath: *const c_char,
            flags: u32,
        ) -> c_int;
    }
    let target_c = path_cstr(target)?;
    let repl_c = path_cstr(replacement)?;
    // SAFETY: `target_c` and `repl_c` are valid NUL-terminated C strings; `AT_FDCWD` (`-100`) and `RENAME_EXCHANGE` (`2`) atomically exchange `replacement` and `target` in kernel VFS so `replacement` now holds the exact displaced inode.
    let rc = unsafe { renameat2(-100, repl_c.as_ptr(), -100, target_c.as_ptr(), 2) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(replacement.to_path_buf())
}

#[cfg(target_os = "macos")]
pub fn atomic_replace_capturing_displaced(
    target: &Path,
    replacement: &Path,
    _displaced_out: &Path,
) -> std::io::Result<PathBuf> {
    extern "C" {
        fn renamex_np(from: *const c_char, to: *const c_char, flags: u32) -> c_int;
    }
    let target_c = path_cstr(target)?;
    let repl_c = path_cstr(replacement)?;
    // SAFETY: `target_c` and `repl_c` are valid NUL-terminated C strings; `RENAME_SWAP` (`2`) atomically swaps `replacement` and `target` so `replacement` now holds the exact displaced inode.
    let rc = unsafe { renamex_np(repl_c.as_ptr(), target_c.as_ptr(), 2) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(replacement.to_path_buf())
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub fn atomic_replace_capturing_displaced(
    _target: &Path,
    _replacement: &Path,
    _displaced_out: &Path,
) -> std::io::Result<PathBuf> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic file swap unsupported on this OS",
    ))
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

pub(crate) fn is_active_v1_lock_file(p: &Path, stale_sec: f64) -> bool {
    p.is_file()
        && !is_v2_lock_artifact(p)
        && !is_lock_file_stale(p, stale_sec)
        && is_v1_slot_owner_possibly_alive(p)
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

#[derive(Clone, Debug, Default)]
pub(crate) struct OsProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub start_token: u64,
    pub same_user: bool,
    pub exe_known: bool,
    pub exe_path: String,
    pub exe_ino: Option<u64>,
    pub cwd_known: bool,
    pub cwd_path: String,
    pub cmdline_known: bool,
    pub cmdline: String,
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn decode_nul_separated_cmdline(raw: &[u8]) -> String {
    // INVARIANT: Decode NUL-delimited UTF-8 argv bytes (`Linux /proc/<pid>/cmdline`, `macOS KERN_PROCARGS2`) via `from_utf8_lossy` after replacing `0x00` with ASCII space so non-ASCII paths (`/home/иван/...`) are preserved verbatim instead of Latin-1 byte-widened.
    let end = raw
        .iter()
        .rposition(|&b| b != 0)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    if end == 0 {
        return String::new();
    }
    let spaced: Vec<u8> = raw[..end]
        .iter()
        .map(|&b| if b == 0 { b' ' } else { b })
        .collect();
    String::from_utf8_lossy(&spaced).into_owned()
}

#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_macos_procargs2(raw: &[u8]) -> Option<String> {
    // INVARIANT: XNU `KERN_PROCARGS2` begins with `argc: i32`, followed by `exec_path\0`, NUL alignment padding, and `argc` NUL-terminated `argv` strings before `envp`; extract strictly `argc` arguments so `envp` variables never pollute `cmdline`.
    if raw.len() < 5 {
        return None;
    }
    let argc = i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if argc <= 0 || argc > 65536 {
        return None;
    }
    let body = &raw[4..];
    let exec_nul = body.iter().position(|&b| b == 0)?;
    let mut pos = exec_nul + 1;
    while pos < body.len() && body[pos] == 0 {
        pos += 1;
    }
    if pos >= body.len() {
        return Some(String::from_utf8_lossy(&body[..exec_nul]).into_owned());
    }
    let mut args_out: Vec<String> = Vec::with_capacity((argc as usize).min(256));
    for _ in 0..(argc as usize) {
        if pos >= body.len() {
            break;
        }
        let end = body[pos..]
            .iter()
            .position(|&b| b == 0)
            .map(|rel| pos + rel)
            .unwrap_or(body.len());
        args_out.push(String::from_utf8_lossy(&body[pos..end]).into_owned());
        pos = end.saturating_add(1);
    }
    if args_out.is_empty() {
        None
    } else {
        Some(args_out.join(" "))
    }
}

pub(crate) fn cmdline_may_need_cwd(raw_cmd: &str) -> bool {
    let lower = raw_cmd.replace('\\', "/").to_lowercase();
    lower.contains(".py")
        || lower.contains("hooks/")
        || lower.contains("scripts/")
        || lower.contains("carbon-stack")
}

#[cfg(windows)]
fn query_nt_info_fn() -> Option<
    unsafe extern "system" fn(
        win_ffi::Handle,
        c_int,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32,
> {
    type NtQueryInfoFn = unsafe extern "system" fn(
        win_ffi::Handle,
        c_int,
        *mut c_void,
        u32,
        *mut u32,
    ) -> i32;
    static FN_CELL: OnceLock<Option<NtQueryInfoFn>> = OnceLock::new();
    *FN_CELL.get_or_init(|| {
        let wide = win_ffi::to_wide("ntdll.dll");
        // SAFETY: `ntdll.dll` is permanently loaded in every Win32 process; `wide` is NUL-terminated UTF-16 and `b"NtQueryInformationProcess\0"` is a static NUL-terminated ASCII symbol name.
        unsafe {
            let hmod = win_ffi::LoadLibraryW(wide.as_ptr());
            if hmod.is_null() {
                return None;
            }
            let sym = win_ffi::GetProcAddress(
                hmod,
                b"NtQueryInformationProcess\0".as_ptr() as *const c_char,
            );
            if sym.is_null() {
                None
            } else {
                Some(std::mem::transmute::<win_ffi::FarProc, NtQueryInfoFn>(sym))
            }
        }
    })
}

#[cfg(windows)]
fn read_win32_cmdline(h_proc: win_ffi::Handle) -> Option<String> {
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }
    let nt_query = query_nt_info_fn()?;
    const PROCESS_COMMAND_LINE_INFORMATION: c_int = 60;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820i32;
    let mut cap_words: usize = 1024;
    for _ in 0..2 {
        let mut buf: Vec<usize> = vec![0usize; cap_words];
        let byte_len = (buf.len() * std::mem::size_of::<usize>()) as u32;
        let mut ret_len: u32 = 0;
        // SAFETY: `buf` is `usize`-aligned with `byte_len` writable bytes; `ProcessCommandLineInformation` (60) marshals `UNICODE_STRING` + UTF-16 payload inside `buf`.
        let status = unsafe {
            nt_query(
                h_proc,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr() as *mut c_void,
                byte_len,
                &mut ret_len,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH
            && (ret_len as usize) > (byte_len as usize)
            && (ret_len as usize) <= 65536
        {
            cap_words = ((ret_len as usize) + std::mem::size_of::<usize>())
                / std::mem::size_of::<usize>();
            continue;
        }
        if status < 0 || (byte_len as usize) < std::mem::size_of::<UnicodeString>() {
            return None;
        }
        // SAFETY: `buf` holds at least `size_of::<UnicodeString>()` initialized bytes at alignment `align_of::<usize>()`.
        let us = unsafe { ptr::read(buf.as_ptr() as *const UnicodeString) };
        let str_bytes = us.length as usize;
        if str_bytes == 0 {
            return Some(String::new());
        }
        if str_bytes % 2 != 0 || us.buffer.is_null() {
            return None;
        }
        let buf_start = buf.as_ptr() as usize;
        let buf_end = buf_start.saturating_add(byte_len as usize);
        let ptr_addr = us.buffer as usize;
        if ptr_addr < buf_start
            || ptr_addr % 2 != 0
            || ptr_addr.saturating_add(str_bytes) > buf_end
        {
            return None;
        }
        // SAFETY: `us.buffer` is 2-byte aligned and points strictly within `buf[..byte_len]`.
        let slice = unsafe { std::slice::from_raw_parts(us.buffer, str_bytes / 2) };
        return Some(String::from_utf16_lossy(slice));
    }
    None
}

#[cfg(all(windows, target_pointer_width = "64"))]
fn read_win32_cwd_x64(pid: u32) -> Option<String> {
    #[repr(C)]
    struct ProcessBasicInformation {
        reserved1: *mut c_void,
        peb_base_address: usize,
        reserved2: [*mut c_void; 2],
        unique_process_id: usize,
        reserved3: *mut c_void,
    }
    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct RemoteUnicodeString64 {
        length: u16,
        maximum_length: u16,
        _pad: u32,
        buffer: usize,
    }
    let nt_query = query_nt_info_fn()?;
    // SAFETY: `OpenProcess` with read-only query/VM flags on `pid` returns NULL on failure; handle is closed before returning.
    let h = unsafe {
        win_ffi::OpenProcess(
            win_ffi::PROCESS_QUERY_INFORMATION | win_ffi::PROCESS_VM_READ,
            0,
            pid,
        )
    };
    if h.is_null() {
        return None;
    }
    let out = (|| -> Option<String> {
        let mut pbi = ProcessBasicInformation {
            reserved1: ptr::null_mut(),
            peb_base_address: 0,
            reserved2: [ptr::null_mut(); 2],
            unique_process_id: 0,
            reserved3: ptr::null_mut(),
        };
        let mut ret_len: u32 = 0;
        // SAFETY: `pbi` matches the x64 `PROCESS_BASIC_INFORMATION` layout (`0`).
        let st = unsafe {
            nt_query(
                h,
                0,
                (&mut pbi as *mut ProcessBasicInformation).cast::<c_void>(),
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        if st < 0 || pbi.peb_base_address == 0 {
            return None;
        }
        let mut proc_params_addr: usize = 0;
        let mut nread: usize = 0;
        // SAFETY: Reads 8-byte `ProcessParameters` pointer at x64 `PEB + 0x20` into stack `proc_params_addr`.
        let ok_pp = unsafe {
            win_ffi::ReadProcessMemory(
                h,
                (pbi.peb_base_address.wrapping_add(0x20)) as *const c_void,
                (&mut proc_params_addr as *mut usize).cast::<c_void>(),
                std::mem::size_of::<usize>(),
                &mut nread,
            )
        };
        if ok_pp == 0 || nread != std::mem::size_of::<usize>() || proc_params_addr == 0 {
            return None;
        }
        let mut flags: u32 = 0;
        // SAFETY: Reads 4-byte `RTL_USER_PROCESS_PARAMETERS.Flags` at `+0x08`.
        let ok_fl = unsafe {
            win_ffi::ReadProcessMemory(
                h,
                (proc_params_addr.wrapping_add(0x08)) as *const c_void,
                (&mut flags as *mut u32).cast::<c_void>(),
                std::mem::size_of::<u32>(),
                &mut nread,
            )
        };
        if ok_fl == 0 || nread != std::mem::size_of::<u32>() {
            return None;
        }
        let mut dos_us = RemoteUnicodeString64::default();
        // SAFETY: Reads 16-byte `CurrentDirectory.DosPath` `UNICODE_STRING` at x64 `RTL_USER_PROCESS_PARAMETERS + 0x38`.
        let ok_us = unsafe {
            win_ffi::ReadProcessMemory(
                h,
                (proc_params_addr.wrapping_add(0x38)) as *const c_void,
                (&mut dos_us as *mut RemoteUnicodeString64).cast::<c_void>(),
                std::mem::size_of::<RemoteUnicodeString64>(),
                &mut nread,
            )
        };
        if ok_us == 0
            || nread != std::mem::size_of::<RemoteUnicodeString64>()
            || dos_us.length == 0
            || dos_us.length % 2 != 0
            || dos_us.length > 8192
            || dos_us.buffer == 0
        {
            return None;
        }
        let remote_buf = if (flags & 1) != 0 {
            dos_us.buffer
        } else {
            proc_params_addr.wrapping_add(dos_us.buffer)
        };
        let u16_len = (dos_us.length as usize) / 2;
        let mut wbuf = vec![0u16; u16_len];
        // SAFETY: `wbuf` has capacity `dos_us.length` bytes (`u16_len * 2`).
        let ok_str = unsafe {
            win_ffi::ReadProcessMemory(
                h,
                remote_buf as *const c_void,
                wbuf.as_mut_ptr().cast::<c_void>(),
                dos_us.length as usize,
                &mut nread,
            )
        };
        if ok_str == 0 || nread != (dos_us.length as usize) {
            return None;
        }
        Some(String::from_utf16_lossy(&wbuf))
    })();
    // SAFETY: Close valid handle returned by `OpenProcess`.
    unsafe {
        win_ffi::CloseHandle(h);
    }
    out
}

pub(crate) fn list_os_processes() -> Result<Vec<OsProcInfo>, String> {
    #[cfg(windows)]
    {
        if query_nt_info_fn().is_none() {
            return Err("NtQueryInformationProcess is unavailable on this Windows host".to_string());
        }
        let mut out = Vec::new();
        let self_pid = std::process::id();
        let mut saw_self = false;
        // SAFETY: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` captures an atomic kernel snapshot of active processes.
        let snap = unsafe { win_ffi::CreateToolhelp32Snapshot(win_ffi::TH32CS_SNAPPROCESS, 0) };
        if snap.is_null() || snap == win_ffi::INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed".to_string());
        }
        // SAFETY: Zero-initialized `ProcessEntry32W` with `dw_size` set per Win32 contract.
        let mut entry: win_ffi::ProcessEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = std::mem::size_of::<win_ffi::ProcessEntry32W>() as u32;
        // SAFETY: Iterates `snap` with valid `entry` buffer until `Process32NextW` returns 0.
        let first_ok = unsafe { win_ffi::Process32FirstW(snap, &mut entry) } != 0;
        if !first_ok {
            // SAFETY: Close Toolhelp snapshot handle before returning error.
            unsafe {
                win_ffi::CloseHandle(snap);
            }
            return Err("Process32FirstW failed on Toolhelp snapshot".to_string());
        }
        let mut has = true;
        while has {
            let pid = entry.th32_process_id;
            let ppid = entry.th32_parent_process_id;
            let nul_pos = entry
                .sz_exe_file
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.sz_exe_file.len());
            let short_exe = String::from_utf16_lossy(&entry.sz_exe_file[..nul_pos]).to_lowercase();
            if pid > 4 {
                // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` queries exit status, start timestamp, image path, and command line; closed before end of scope.
                let h = unsafe {
                    win_ffi::OpenProcess(win_ffi::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
                };
                if !h.is_null() {
                    let mut code: win_ffi::Dword = 0;
                    // SAFETY: Queries process exit code on valid handle `h`.
                    let alive = unsafe { win_ffi::GetExitCodeProcess(h, &mut code) } != 0
                        && code == win_ffi::STILL_ACTIVE;
                    if alive {
                        let mut c_ft = win_ffi::WinFileTime::default();
                        let mut e_ft = win_ffi::WinFileTime::default();
                        let mut k_ft = win_ffi::WinFileTime::default();
                        let mut u_ft = win_ffi::WinFileTime::default();
                        // SAFETY: Queries process creation timestamp on valid handle `h`.
                        let start_token = if unsafe {
                            win_ffi::GetProcessTimes(h, &mut c_ft, &mut e_ft, &mut k_ft, &mut u_ft)
                        } != 0
                        {
                            ((c_ft.dw_high_date_time as u64) << 32) | (c_ft.dw_low_date_time as u64)
                        } else {
                            0
                        };
                        let mut img_buf = vec![0u16; 2048];
                        let mut img_len = img_buf.len() as u32;
                        // SAFETY: `img_buf` holds `img_len` `u16` elements for Win32 path output.
                        let (exe_known, exe_path) = if unsafe {
                            win_ffi::QueryFullProcessImageNameW(
                                h,
                                0,
                                img_buf.as_mut_ptr(),
                                &mut img_len,
                            )
                        } != 0
                        {
                            (true, String::from_utf16_lossy(&img_buf[..img_len as usize]))
                        } else {
                            (false, String::new())
                        };
                        let cmd_opt = read_win32_cmdline(h);
                        let (cmdline_known, cmdline) = match cmd_opt {
                            Some(s) => (true, s),
                            None => (false, String::new()),
                        };
                        let need_cwd = pid == self_pid
                            || !cmdline_known
                            || cmdline_may_need_cwd(&cmdline)
                            || short_exe.contains("python")
                            || short_exe == "py.exe"
                            || short_exe.contains("carbon-stack");
                        #[cfg(target_pointer_width = "64")]
                        let (cwd_known, cwd_path) = if need_cwd {
                            match read_win32_cwd_x64(pid) {
                                Some(c) => (true, c),
                                None => (false, String::new()),
                            }
                        } else {
                            (false, String::new())
                        };
                        #[cfg(not(target_pointer_width = "64"))]
                        let (cwd_known, cwd_path) = (false, String::new());

                        // SAFETY: Probe `PROCESS_QUERY_INFORMATION` to distinguish same-user accessible processes from elevated/system pseudo-processes.
                        let h_full = unsafe {
                            win_ffi::OpenProcess(win_ffi::PROCESS_QUERY_INFORMATION, 0, pid)
                        };
                        let full_query_ok = if h_full.is_null() {
                            false
                        } else {
                            // SAFETY: Close probe handle immediately.
                            unsafe {
                                win_ffi::CloseHandle(h_full);
                            }
                            true
                        };
                        let mut code_after: win_ffi::Dword = 0;
                        // SAFETY: Re-verify `STILL_ACTIVE` so a process that exited mid-read is not flagged as an incomplete live process.
                        let still_alive_after =
                            unsafe { win_ffi::GetExitCodeProcess(h, &mut code_after) } != 0
                                && code_after == win_ffi::STILL_ACTIVE;
                        if still_alive_after {
                            let is_user_candidate = pid == self_pid
                                || (full_query_ok && exe_known)
                                || short_exe.contains("python")
                                || short_exe == "py.exe"
                                || short_exe.contains("carbon-stack");
                            if pid == self_pid {
                                saw_self = true;
                            }
                            out.push(OsProcInfo {
                                pid,
                                ppid,
                                start_token,
                                same_user: is_user_candidate,
                                exe_known,
                                exe_path,
                                exe_ino: None,
                                cwd_known,
                                cwd_path,
                                cmdline_known,
                                cmdline,
                            });
                        }
                    }
                    // SAFETY: Close `OpenProcess` handle `h`.
                    unsafe {
                        win_ffi::CloseHandle(h);
                    }
                } else if short_exe.contains("python")
                    || short_exe == "py.exe"
                    || short_exe.contains("carbon-stack")
                {
                    out.push(OsProcInfo {
                        pid,
                        ppid,
                        start_token: 0,
                        same_user: true,
                        exe_known: false,
                        exe_path: short_exe,
                        exe_ino: None,
                        cwd_known: false,
                        cwd_path: String::new(),
                        cmdline_known: false,
                        cmdline: String::new(),
                    });
                } else {
                    out.push(OsProcInfo {
                        pid,
                        ppid,
                        start_token: 0,
                        same_user: false,
                        exe_known: false,
                        exe_path: String::new(),
                        exe_ino: None,
                        cwd_known: false,
                        cwd_path: String::new(),
                        cmdline_known: false,
                        cmdline: String::new(),
                    });
                }
            }
            // SAFETY: Advance Toolhelp snapshot iterator.
            has = unsafe { win_ffi::Process32NextW(snap, &mut entry) } != 0;
        }
        // SAFETY: Close Toolhelp snapshot handle.
        unsafe {
            win_ffi::CloseHandle(snap);
        }
        if !saw_self {
            return Err("Current process missing from Windows Toolhelp process snapshot".to_string());
        }
        Ok(out)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let self_pid = std::process::id();
        let self_uid = fs::metadata(Path::new("/proc/self"))
            .map_err(|e| format!("Cannot stat /proc/self: {}", e))?
            .uid();
        let rd = fs::read_dir(Path::new("/proc"))
            .map_err(|e| format!("Cannot read /proc: {}", e))?;
        let mut out = Vec::new();
        let mut saw_self = false;
        for ent_res in rd {
            let ent = ent_res.map_err(|e| format!("Error iterating /proc: {}", e))?;
            let Ok(pid) = ent.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let proc_dir = ent.path();
            let dir_meta = match fs::metadata(&proc_dir) {
                Ok(m) => m,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("Cannot stat {}: {}", proc_dir.display(), e)),
            };
            let same_user = dir_meta.uid() == self_uid;
            let stat_txt = match fs::read_to_string(proc_dir.join("stat")) {
                Ok(s) => s,
                Err(_) if !proc_dir.exists() => continue,
                Err(e) if same_user => {
                    return Err(format!("Cannot read /proc/{}/stat: {}", pid, e));
                }
                Err(_) => continue,
            };
            let Some(rparen) = stat_txt.rfind(')') else {
                continue;
            };
            let after: Vec<&str> = stat_txt[rparen + 1..].split_whitespace().collect();
            let Some(&state_s) = after.first() else {
                continue;
            };
            if state_s.starts_with('Z') || state_s.starts_with('X') {
                continue;
            }
            let flags = after
                .get(6)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            const PF_KTHREAD: u64 = 0x0020_0000;
            if (flags & PF_KTHREAD) != 0 {
                continue;
            }
            let ppid = after.get(1).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
            let start_token = after
                .get(19)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let exe_link = proc_dir.join("exe");
            let (exe_known, exe_path) = match fs::read_link(&exe_link) {
                Ok(p) => (true, p.to_string_lossy().into_owned()),
                Err(_) => (false, String::new()),
            };
            let exe_ino = fs::metadata(&exe_link).ok().map(|m| m.ino());
            let (cmdline_known, cmdline) = match fs::read(proc_dir.join("cmdline")) {
                Ok(raw) => (true, decode_nul_separated_cmdline(&raw)),
                Err(_) => (false, String::new()),
            };
            let (cwd_known, cwd_path) = if same_user {
                match fs::read_link(proc_dir.join("cwd")) {
                    Ok(p) => (true, p.to_string_lossy().into_owned()),
                    Err(_) => (false, String::new()),
                }
            } else {
                (false, String::new())
            };
            if (!exe_known || !cmdline_known || (same_user && !cwd_known)) && !proc_dir.exists() {
                continue;
            }
            if pid == self_pid {
                saw_self = true;
            }
            out.push(OsProcInfo {
                pid,
                ppid,
                start_token,
                same_user,
                exe_known,
                exe_path,
                exe_ino,
                cwd_known,
                cwd_path,
                cmdline_known,
                cmdline,
            });
        }
        if !saw_self {
            return Err("Current process missing from /proc scan".to_string());
        }
        Ok(out)
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        const PROC_ALL_PIDS: u32 = 1;
        const PROC_PIDTBSDINFO: c_int = 3;
        const PROC_PIDVNODEPATHINFO: c_int = 9;
        const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;
        const SZOMB: u32 = 5;
        const CTL_KERN: c_int = 1;
        const KERN_PROCARGS2: c_int = 49;

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct ProcBsdInfo {
            pbi_flags: u32,
            pbi_status: u32,
            pbi_xstatus: u32,
            pbi_pid: u32,
            pbi_ppid: u32,
            pbi_uid: u32,
            pbi_gid: u32,
            pbi_ruid: u32,
            pbi_rgid: u32,
            pbi_svuid: u32,
            pbi_svgid: u32,
            rfu_1: u32,
            pbi_comm: [c_char; 16],
            pbi_name: [c_char; 32],
            pbi_nfiles: u32,
            pbi_pgid: u32,
            pbi_pjobc: u32,
            e_tdev: u32,
            e_tpgid: u32,
            pbi_nice: i32,
            pbi_start_tvsec: u64,
            pbi_start_tvusec: u64,
        }

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct VinfoStat {
            vst_dev: u32,
            vst_mode: u16,
            vst_nlink: u16,
            vst_ino: u64,
            vst_uid: u32,
            vst_gid: u32,
            vst_atime: i64,
            vst_atimensec: i64,
            vst_mtime: i64,
            vst_mtimensec: i64,
            vst_ctime: i64,
            vst_ctimensec: i64,
            vst_birthtime: i64,
            vst_birthtimensec: i64,
            vst_size: i64,
            vst_blocks: i64,
            vst_blksize: i32,
            vst_flags: u32,
            vst_gen: u32,
            vst_rdev: u32,
            vst_qspare: [i64; 2],
        }

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct VnodeInfo {
            vi_stat: VinfoStat,
            vi_type: c_int,
            vi_pad: c_int,
            vi_fsid: [i32; 2],
        }

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct VnodeInfoPath {
            vip_vi: VnodeInfo,
            vip_path: [c_char; 1024],
        }

        #[repr(C)]
        #[derive(Copy, Clone)]
        struct ProcVnodePathInfo {
            pvi_cdir: VnodeInfoPath,
            pvi_rdir: VnodeInfoPath,
        }

        extern "C" {
            fn geteuid() -> u32;
            fn kill(pid: i32, sig: c_int) -> c_int;
            fn __error() -> *mut c_int;
            fn proc_listpids(
                kind: u32,
                typeinfo: u32,
                buffer: *mut c_void,
                buffersize: c_int,
            ) -> c_int;
            fn proc_pidinfo(
                pid: c_int,
                flavor: c_int,
                arg: u64,
                buffer: *mut c_void,
                buffersize: c_int,
            ) -> c_int;
            fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
            fn sysctl(
                name: *mut c_int,
                namelen: u32,
                oldp: *mut c_void,
                oldlenp: *mut usize,
                newp: *mut c_void,
                newlen: usize,
            ) -> c_int;
        }

        // SAFETY: `geteuid()` is a thread-safe POSIX syscall with no pointer arguments.
        let self_uid = unsafe { geteuid() };
        let self_pid = std::process::id();
        // SAFETY: Passing NULL buffer queries an upper-bound byte capacity for active PIDs.
        let est_bytes = unsafe { proc_listpids(PROC_ALL_PIDS, 0, ptr::null_mut(), 0) };
        if est_bytes <= 0 {
            return Err("macOS proc_listpids size query failed".to_string());
        }
        let mut cap_pids = ((est_bytes as usize) / std::mem::size_of::<i32>()).max(256) * 2;
        let pids: Vec<i32> = loop {
            let mut buf = vec![0i32; cap_pids];
            let byte_cap = (buf.len() * std::mem::size_of::<i32>()) as c_int;
            // SAFETY: `buf` has `byte_cap` writable bytes aligned for `i32` PIDs.
            let got_bytes = unsafe {
                proc_listpids(
                    PROC_ALL_PIDS,
                    0,
                    buf.as_mut_ptr().cast::<c_void>(),
                    byte_cap,
                )
            };
            if got_bytes <= 0 {
                return Err("macOS proc_listpids failed".to_string());
            }
            let count = (got_bytes as usize) / std::mem::size_of::<i32>();
            if count >= buf.len() && cap_pids < 262_144 {
                cap_pids *= 2;
                continue;
            }
            buf.truncate(count);
            break buf;
        };

        let mut out = Vec::new();
        let mut saw_self = false;
        for raw_pid in pids {
            if raw_pid <= 0 {
                continue;
            }
            let pid = raw_pid as u32;
            // SAFETY: Zero-initialized `ProcBsdInfo` matches XNU `struct proc_bsdinfo` (`136` bytes).
            let mut bsd: ProcBsdInfo = unsafe { std::mem::zeroed() };
            let bsd_sz = std::mem::size_of::<ProcBsdInfo>() as c_int;
            // SAFETY: `bsd` has exact size `bsd_sz`.
            let rc = unsafe {
                proc_pidinfo(
                    raw_pid,
                    PROC_PIDTBSDINFO,
                    0,
                    (&mut bsd as *mut ProcBsdInfo).cast::<c_void>(),
                    bsd_sz,
                )
            };
            if rc <= 0 {
                // SAFETY: Reads thread-local `errno` (`ESRCH == 3`) and probes `kill(pid, 0)` to distinguish exited/foreign PIDs from unexpected `libproc` failures on owned processes.
                let (err_no, can_sig) = unsafe { (*__error(), kill(raw_pid, 0) == 0) };
                if err_no == 3 {
                    continue;
                }
                if can_sig {
                    return Err(format!(
                        "macOS proc_pidinfo(PROC_PIDTBSDINFO) failed for live pid {} (errno={})",
                        pid, err_no
                    ));
                }
                continue;
            }
            if rc != bsd_sz {
                return Err("macOS proc_bsdinfo size mismatch".to_string());
            }
            if bsd.pbi_status == SZOMB {
                continue;
            }
            let same_user = bsd.pbi_uid == self_uid || bsd.pbi_ruid == self_uid;
            let start_token = bsd
                .pbi_start_tvsec
                .wrapping_mul(1_000_000)
                .wrapping_add(bsd.pbi_start_tvusec);
            if !same_user {
                out.push(OsProcInfo {
                    pid,
                    ppid: bsd.pbi_ppid,
                    start_token,
                    same_user: false,
                    exe_known: false,
                    exe_path: String::new(),
                    exe_ino: None,
                    cwd_known: false,
                    cwd_path: String::new(),
                    cmdline_known: false,
                    cmdline: String::new(),
                });
                continue;
            }

            let mut path_buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE as usize];
            // SAFETY: `path_buf` has `PROC_PIDPATHINFO_MAXSIZE` writable bytes.
            let path_len = unsafe {
                proc_pidpath(
                    raw_pid,
                    path_buf.as_mut_ptr().cast::<c_void>(),
                    PROC_PIDPATHINFO_MAXSIZE,
                )
            };
            let (exe_known, exe_path) = if path_len > 0 {
                let slice = &path_buf[..(path_len as usize).min(path_buf.len())];
                let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
                (true, String::from_utf8_lossy(&slice[..end]).into_owned())
            } else {
                (false, String::new())
            };
            let exe_ino = if exe_known && exe_path.contains("carbon-stack") {
                fs::metadata(&exe_path).ok().map(|m| m.ino())
            } else {
                None
            };

            let mut mib = [CTL_KERN, KERN_PROCARGS2, raw_pid];
            let mut arg_sz: usize = 65536;
            let mut arg_buf = vec![0u8; arg_sz];
            // SAFETY: `mib` has 3 ints and `arg_buf` has `arg_sz` writable bytes for `KERN_PROCARGS2`.
            let mut sys_rc = unsafe {
                sysctl(
                    mib.as_mut_ptr(),
                    3,
                    arg_buf.as_mut_ptr().cast::<c_void>(),
                    &mut arg_sz,
                    ptr::null_mut(),
                    0,
                )
            };
            if sys_rc != 0 {
                let mut req_sz: usize = 0;
                // SAFETY: Queries required buffer size for `KERN_PROCARGS2` when > 64 KiB.
                if unsafe {
                    sysctl(
                        mib.as_mut_ptr(),
                        3,
                        ptr::null_mut(),
                        &mut req_sz,
                        ptr::null_mut(),
                        0,
                    )
                } == 0
                    && req_sz > arg_buf.len()
                    && req_sz <= 262_144
                {
                    arg_sz = req_sz;
                    arg_buf.resize(arg_sz, 0);
                    // SAFETY: Retries `KERN_PROCARGS2` with `arg_sz`-byte buffer.
                    sys_rc = unsafe {
                        sysctl(
                            mib.as_mut_ptr(),
                            3,
                            arg_buf.as_mut_ptr().cast::<c_void>(),
                            &mut arg_sz,
                            ptr::null_mut(),
                            0,
                        )
                    };
                }
            }
            let (cmdline_known, cmdline) = if sys_rc == 0 && arg_sz > 0 {
                let used = arg_sz.min(arg_buf.len());
                match parse_macos_procargs2(&arg_buf[..used]) {
                    Some(s) => (true, s),
                    None => (false, String::new()),
                }
            } else {
                (false, String::new())
            };

            let need_cwd = pid == self_pid || !cmdline_known || cmdline_may_need_cwd(&cmdline);
            let (cwd_known, cwd_path) = if need_cwd {
                // SAFETY: Zero-initialized `ProcVnodePathInfo` matches XNU `struct proc_vnodepathinfo` (`2352` bytes).
                let mut vpi: ProcVnodePathInfo = unsafe { std::mem::zeroed() };
                let vpi_sz = std::mem::size_of::<ProcVnodePathInfo>() as c_int;
                // SAFETY: `vpi` has exact size `vpi_sz`.
                let vrc = unsafe {
                    proc_pidinfo(
                        raw_pid,
                        PROC_PIDVNODEPATHINFO,
                        0,
                        (&mut vpi as *mut ProcVnodePathInfo).cast::<c_void>(),
                        vpi_sz,
                    )
                };
                if vrc == vpi_sz {
                    // SAFETY: `vip_path` is a `[c_char; 1024]` array inside stack-allocated `vpi`.
                    let raw_bytes: &[u8] = unsafe {
                        std::slice::from_raw_parts(
                            vpi.pvi_cdir.vip_path.as_ptr().cast::<u8>(),
                            vpi.pvi_cdir.vip_path.len(),
                        )
                    };
                    let end = raw_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(raw_bytes.len());
                    if end > 0 {
                        (true, String::from_utf8_lossy(&raw_bytes[..end]).into_owned())
                    } else {
                        (false, String::new())
                    }
                } else {
                    (false, String::new())
                }
            } else {
                (false, String::new())
            };

            if !exe_known || !cmdline_known || (need_cwd && !cwd_known) {
                // SAFETY: `ProcBsdInfo` is a `#[repr(C)]` plain-old-data struct of primitive integer and fixed-array fields for which an all-zero bit pattern is valid.
                let mut bsd_after: ProcBsdInfo = unsafe { std::mem::zeroed() };
                // SAFETY: `bsd_after` is a properly aligned writable `ProcBsdInfo` buffer of exact byte size `bsd_sz`; re-querying `PROC_PIDTBSDINFO` skips processes that exited or became `SZOMB` mid-inspection.
                let rc_after = unsafe {
                    proc_pidinfo(
                        raw_pid,
                        PROC_PIDTBSDINFO,
                        0,
                        (&mut bsd_after as *mut ProcBsdInfo).cast::<c_void>(),
                        bsd_sz,
                    )
                };
                if rc_after <= 0 || bsd_after.pbi_status == SZOMB {
                    continue;
                }
            }

            if pid == self_pid {
                saw_self = true;
            }
            out.push(OsProcInfo {
                pid,
                ppid: bsd.pbi_ppid,
                start_token,
                same_user: true,
                exe_known,
                exe_path,
                exe_ino,
                cwd_known,
                cwd_path,
                cmdline_known,
                cmdline,
            });
        }
        if !saw_self {
            return Err("Current process missing from macOS proc_listpids scan".to_string());
        }
        Ok(out)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        Err("Unsupported operating system for legacy v1 process inspection".to_string())
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

    #[test]
    fn test_utf8_cmdline_decoders_and_os_process_table() {
        let linux_raw = "python3\0/home/иван/.gemini/config/plugins/gemini-carbon-stack/hooks/codex_lane.py\0--flag\0".as_bytes();
        assert_eq!(
            decode_nul_separated_cmdline(linux_raw),
            "python3 /home/иван/.gemini/config/plugins/gemini-carbon-stack/hooks/codex_lane.py --flag"
        );
        assert_eq!(decode_nul_separated_cmdline(b"\0\0"), "");

        let mut mac_raw = Vec::new();
        mac_raw.extend_from_slice(&2i32.to_ne_bytes());
        mac_raw.extend_from_slice(b"/usr/bin/python3\0\0\0\0");
        mac_raw.extend_from_slice("python3\0/Users/иван/.gemini/config/plugins/gemini-carbon-stack/hooks/cwg_stop.py\0".as_bytes());
        mac_raw.extend_from_slice(b"PATH=/usr/bin\0LEAK=/unrelated/gemini-carbon-stack/hooks/evil.py\0");
        let parsed_mac = parse_macos_procargs2(&mac_raw).unwrap();
        assert_eq!(
            parsed_mac,
            "python3 /Users/иван/.gemini/config/plugins/gemini-carbon-stack/hooks/cwg_stop.py"
        );
        assert!(!parsed_mac.contains("LEAK="));

        let procs = list_os_processes().unwrap();
        let me = procs.iter().find(|p| p.pid == std::process::id()).unwrap();
        assert!(me.same_user);
        assert!(me.exe_known && !me.exe_path.is_empty());
        assert!(me.cmdline_known);
        assert!(me.cwd_known && !me.cwd_path.is_empty());
    }
}
