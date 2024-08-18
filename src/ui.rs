use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/amjdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/amjdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/accamj/amjdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAMd2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDUgNzkuMTYzNDk5LCAyMDE4LzA4LzEzLTE2OjQwOjIyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIiB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDI0LTA3LTA4VDE1OjA2OjIxKzAzOjMwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyNC0wNy0xM1QxMjozNTowNCswMzozMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyNC0wNy0xM1QxMjozNTowNCswMzozMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpiNjYwNjEyZS0wYTVhLWE2NGQtYTc5Yi1iYTk1ZGYxNGI4YjEiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDozYTI2ZjFiYi1mOGJiLWY1NGQtYWQzNS01YmYwMjQ1NjliOTUiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo2YmExOGVjZC0xMTFlLTEyNDYtOTI2Mi1kNTczYTU1YjFjZjQiIHRpZmY6T3JpZW50YXRpb249IjEiIHRpZmY6WFJlc29sdXRpb249IjcyMDAwMC8xMDAwMCIgdGlmZjpZUmVzb2x1dGlvbj0iNzIwMDAwLzEwMDAwIiB0aWZmOlJlc29sdXRpb25Vbml0PSIyIiBleGlmOkNvbG9yU3BhY2U9IjEiIGV4aWY6UGl4ZWxYRGltZW5zaW9uPSIxMDI0IiBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTAyNCI+IDxwaG90b3Nob3A6VGV4dExheWVycz4gPHJkZjpCYWc+IDxyZGY6bGkgcGhvdG9zaG9wOkxheWVyTmFtZT0iRCAgICBFICAgIFMgICAgSyIgcGhvdG9zaG9wOkxheWVyVGV4dD0iRCAgICBFICAgIFMgICAgSyIvPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOlRleHRMYXllcnM+IDxwaG90b3Nob3A6RG9jdW1lbnRBbmNlc3RvcnM+IDxyZGY6QmFnPiA8cmRmOmxpPnhtcC5kaWQ6OTFjYzVjN2ItOTY2NC0wMzQxLWI3ZGUtMmE0ZjdiNTZhMGQ1PC9yZGY6bGk+IDxyZGY6bGk+eG1wLmRpZDpBRUFDQUVCRTQwN0ZFMjExQTBCRDlBRkM2MEUyN0VGODwvcmRmOmxpPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjcmVhdGVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjZiYTE4ZWNkLTExMWUtMTI0Ni05MjYyLWQ1NzNhNTViMWNmNCIgc3RFdnQ6d2hlbj0iMjAyNC0wNy0wOFQxNTowNjoyMSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjb252ZXJ0ZWQiIHN0RXZ0OnBhcmFtZXRlcnM9ImZyb20gaW1hZ2UvcG5nIHRvIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5waG90b3Nob3AiLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjJmYTU2ZTdhLThiZWEtMjI0MC1hNWVkLWVmZGQxN2U3MDNkZiIgc3RFdnQ6d2hlbj0iMjAyNC0wNy0wOVQxMDozNzo1OSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo0MWMxZWQ2NC0wYmU2LWIyNDgtOGE1Yy1hOWYwYTJhZDMzY2EiIHN0RXZ0OndoZW49IjIwMjQtMDctMTNUMTI6MzU6MDQrMDM6MzAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE5IChXaW5kb3dzKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0iY29udmVydGVkIiBzdEV2dDpwYXJhbWV0ZXJzPSJmcm9tIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5waG90b3Nob3AgdG8gaW1hZ2UvcG5nIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJkZXJpdmVkIiBzdEV2dDpwYXJhbWV0ZXJzPSJjb252ZXJ0ZWQgZnJvbSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9z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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAMd2lUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS42LWMxNDUgNzkuMTYzNDk5LCAyMDE4LzA4LzEzLTE2OjQwOjIyICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtbG5zOnRpZmY9Imh0dHA6Ly9ucy5hZG9iZS5jb20vdGlmZi8xLjAvIiB4bWxuczpleGlmPSJodHRwOi8vbnMuYWRvYmUuY29tL2V4aWYvMS4wLyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ0MgMjAxOSAoV2luZG93cykiIHhtcDpDcmVhdGVEYXRlPSIyMDI0LTA3LTA4VDE1OjA2OjIxKzAzOjMwIiB4bXA6TW9kaWZ5RGF0ZT0iMjAyNC0wNy0xM1QxMjozNTowNCswMzozMCIgeG1wOk1ldGFkYXRhRGF0ZT0iMjAyNC0wNy0xM1QxMjozNTowNCswMzozMCIgZGM6Zm9ybWF0PSJpbWFnZS9wbmciIHBob3Rvc2hvcDpDb2xvck1vZGU9IjMiIHBob3Rvc2hvcDpJQ0NQcm9maWxlPSJzUkdCIElFQzYxOTY2LTIuMSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpiNjYwNjEyZS0wYTVhLWE2NGQtYTc5Yi1iYTk1ZGYxNGI4YjEiIHhtcE1NOkRvY3VtZW50SUQ9ImFkb2JlOmRvY2lkOnBob3Rvc2hvcDozYTI2ZjFiYi1mOGJiLWY1NGQtYWQzNS01YmYwMjQ1NjliOTUiIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo2YmExOGVjZC0xMTFlLTEyNDYtOTI2Mi1kNTczYTU1YjFjZjQiIHRpZmY6T3JpZW50YXRpb249IjEiIHRpZmY6WFJlc29sdXRpb249IjcyMDAwMC8xMDAwMCIgdGlmZjpZUmVzb2x1dGlvbj0iNzIwMDAwLzEwMDAwIiB0aWZmOlJlc29sdXRpb25Vbml0PSIyIiBleGlmOkNvbG9yU3BhY2U9IjEiIGV4aWY6UGl4ZWxYRGltZW5zaW9uPSIxMDI0IiBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTAyNCI+IDxwaG90b3Nob3A6VGV4dExheWVycz4gPHJkZjpCYWc+IDxyZGY6bGkgcGhvdG9zaG9wOkxheWVyTmFtZT0iRCAgICBFICAgIFMgICAgSyIgcGhvdG9zaG9wOkxheWVyVGV4dD0iRCAgICBFICAgIFMgICAgSyIvPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOlRleHRMYXllcnM+IDxwaG90b3Nob3A6RG9jdW1lbnRBbmNlc3RvcnM+IDxyZGY6QmFnPiA8cmRmOmxpPnhtcC5kaWQ6OTFjYzVjN2ItOTY2NC0wMzQxLWI3ZGUtMmE0ZjdiNTZhMGQ1PC9yZGY6bGk+IDxyZGY6bGk+eG1wLmRpZDpBRUFDQUVCRTQwN0ZFMjExQTBCRDlBRkM2MEUyN0VGODwvcmRmOmxpPiA8L3JkZjpCYWc+IDwvcGhvdG9zaG9wOkRvY3VtZW50QW5jZXN0b3JzPiA8eG1wTU06SGlzdG9yeT4gPHJkZjpTZXE+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjcmVhdGVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjZiYTE4ZWNkLTExMWUtMTI0Ni05MjYyLWQ1NzNhNTViMWNmNCIgc3RFdnQ6d2hlbj0iMjAyNC0wNy0wOFQxNTowNjoyMSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJjb252ZXJ0ZWQiIHN0RXZ0OnBhcmFtZXRlcnM9ImZyb20gaW1hZ2UvcG5nIHRvIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5waG90b3Nob3AiLz4gPHJkZjpsaSBzdEV2dDphY3Rpb249InNhdmVkIiBzdEV2dDppbnN0YW5jZUlEPSJ4bXAuaWlkOjJmYTU2ZTdhLThiZWEtMjI0MC1hNWVkLWVmZGQxN2U3MDNkZiIgc3RFdnQ6d2hlbj0iMjAyNC0wNy0wOVQxMDozNzo1OSswMzozMCIgc3RFdnQ6c29mdHdhcmVBZ2VudD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTkgKFdpbmRvd3MpIiBzdEV2dDpjaGFuZ2VkPSIvIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJzYXZlZCIgc3RFdnQ6aW5zdGFuY2VJRD0ieG1wLmlpZDo0MWMxZWQ2NC0wYmU2LWIyNDgtOGE1Yy1hOWYwYTJhZDMzY2EiIHN0RXZ0OndoZW49IjIwMjQtMDctMTNUMTI6MzU6MDQrMDM6MzAiIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFkb2JlIFBob3Rvc2hvcCBDQyAyMDE5IChXaW5kb3dzKSIgc3RFdnQ6Y2hhbmdlZD0iLyIvPiA8cmRmOmxpIHN0RXZ0OmFjdGlvbj0iY29udmVydGVkIiBzdEV2dDpwYXJhbWV0ZXJzPSJmcm9tIGFwcGxpY2F0aW9uL3ZuZC5hZG9iZS5waG90b3Nob3AgdG8gaW1hZ2UvcG5nIi8+IDxyZGY6bGkgc3RFdnQ6YWN0aW9uPSJkZXJpdmVkIiBzdEV2dDpwYXJhbWV0ZXJzPSJjb252ZXJ0ZWQgZnJvbSBhcHBsaWNhdGlvbi92bmQuYWRvYmUucGhvdG9z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".into()
    }
}
