use std::sync::{mpsc::{channel, Receiver}, Arc};
use std::time::Duration;

use eframe::egui::{self, CornerRadius, FontData, FontFamily, FontId, Margin, RichText, Stroke, Ui};
use windows_sys::Win32::System::Diagnostics::Debug::Beep;
use windows_sys::Win32::System::Memory::{VirtualAllocEx, VirtualProtectEx};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetAsyncKeyState;

use crate::cheat::{Cheat, CheatValue};
use crate::process;
use crate::scanner::{self, PointerCandidate, ScanEvent, ScanPass};

const GAME_EXE: &str = "re2.exe";
const MAX_ROWS: usize = 200;
const FN_RVA: usize = 0xA1A35E;
const VK_NUMPAD1: i32 = 0x61;
const VK_F1: i32 = 0x70;

const BG: egui::Color32 = egui::Color32::from_rgb(10, 10, 14);
const CARD: egui::Color32 = egui::Color32::from_rgb(17, 17, 24);
const CARD2: egui::Color32 = egui::Color32::from_rgb(23, 23, 32);
const CARD_BORDER: egui::Color32 = egui::Color32::from_rgb(42, 42, 56);
const TXT: egui::Color32 = egui::Color32::from_rgb(232, 234, 242);
const MUTED: egui::Color32 = egui::Color32::from_rgb(132, 138, 160);
const ACCENT: egui::Color32 = egui::Color32::from_rgb(0, 255, 157);
const PINK: egui::Color32 = egui::Color32::from_rgb(255, 46, 136);
const BAD: egui::Color32 = egui::Color32::from_rgb(255, 96, 108);
const INACTIVE_BG: egui::Color32 = egui::Color32::from_rgb(30, 30, 42);

enum AttachEvent {
    Found {
        pid: u32,
        handle: process::ProcessHandle,
        module: Option<(String, usize)>,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Good,
    Bad,
}

struct LogEntry {
    time: String,
    level: LogLevel,
    msg: String,
}

fn attach_worker(tx: std::sync::mpsc::Sender<AttachEvent>) {
    loop {
        if let Some(pid) = process::find_process(GAME_EXE) {
            if let Some(h) = process::open_process(pid) {
                let modules = process::modules(pid);
                let module = modules
                    .iter()
                    .find(|(name, _, _)| name.to_lowercase().starts_with("re_chunk"))
                    .or_else(|| modules.first())
                    .map(|(name, base, _)| (name.clone(), *base));
                let _ = tx.send(AttachEvent::Found { pid, handle: h, module });
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

fn now_tag() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() % 86400)
        .unwrap_or(0);
    let (s, m, h) = (t % 60, (t / 60) % 60, t / 3600);
    format!("{h:02}:{m:02}:{s:02}")
}

pub struct TrainerApp {
    pid: Option<u32>,
    handle: Option<process::ProcessHandle>,
    module_name: Option<String>,
    module_base: Option<usize>,
    attached: bool,
    status: String,
    attach_rx: Option<Receiver<AttachEvent>>,
    attach_started: bool,
    cheats: Vec<Cheat>,
    tick_addrs: Vec<usize>,
    rx: Option<Receiver<ScanEvent>>,
    busy: Option<String>,
    scan_init: f32,
    prev: Vec<(usize, f32)>,
    pointer_results: Vec<PointerCandidate>,
    infinite_enabled: bool,
    hook_flag: Option<usize>,
    key_inf_down: bool,
    logs: Vec<LogEntry>,
    slogan: String,
    bold_family: FontFamily,
}

impl TrainerApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        let mut bold_ok = false;
        for (slot, file) in [
            ("segoe", "segoeui.ttf"),
            ("segoebold", "segoeuib.ttf"),
            ("segoelight", "seguisl.ttf"),
            ("consola", "consola.ttf"),
        ] {
            let full = format!(r"C:\Windows\Fonts\{file}");
            if let Ok(bytes) = std::fs::read(&full) {
                if slot == "segoebold" {
                    bold_ok = true;
                }
                fonts.font_data.insert(
                    slot.to_string(),
                    Arc::new(FontData::from_owned(bytes)),
                );
                match slot {
                    "segoe" => {
                        if let Some(list) = fonts.families.get_mut(&FontFamily::Proportional) {
                            list.insert(0, slot.to_string());
                        }
                    }
                    "consola" => {
                        if let Some(list) = fonts.families.get_mut(&FontFamily::Monospace) {
                            list.insert(0, slot.to_string());
                        }
                    }
                    "segoebold" => {
                        fonts.families.insert(
                            FontFamily::Name(Arc::from("segoebold")),
                            vec!["segoebold".to_string()],
                        );
                    }
                    "segoelight" => {
                        fonts.families.insert(
                            FontFamily::Name(Arc::from("segoelight")),
                            vec!["segoelight".to_string()],
                        );
                    }
                    _ => {}
                }
            }
        }

        let mut style = egui::Style {
            visuals: egui::Visuals::dark(),
            ..Default::default()
        };
        style.text_styles.insert(egui::TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        style.text_styles.insert(egui::TextStyle::Button, FontId::new(15.0, FontFamily::Proportional));
        style.text_styles.insert(egui::TextStyle::Small, FontId::new(11.5, FontFamily::Proportional));
        style.text_styles.insert(egui::TextStyle::Monospace, FontId::new(12.0, FontFamily::Monospace));
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(
                24.0,
                if bold_ok {
                    FontFamily::Name(Arc::from("segoebold"))
                } else {
                    FontFamily::Proportional
                },
            ),
        );
        let bold_family = if bold_ok {
            FontFamily::Name(Arc::from("segoebold"))
        } else {
            FontFamily::Proportional
        };

        let v = &mut style.visuals;
        v.dark_mode = true;
        v.override_text_color = Some(TXT);
        v.panel_fill = BG;
        v.window_fill = CARD;
        v.extreme_bg_color = BG;
        v.faint_bg_color = CARD2;
        v.weak_text_color = Some(MUTED);
        v.hyperlink_color = ACCENT;
        v.selection.bg_fill = egui::Color32::from_rgb(0, 90, 60);
        v.selection.stroke = Stroke::new(1.0, ACCENT);
        for w in [&mut v.widgets.noninteractive, &mut v.widgets.inactive] {
            w.corner_radius = CornerRadius::same(6);
            w.bg_fill = INACTIVE_BG;
            w.weak_bg_fill = CARD2;
            w.bg_stroke = Stroke::new(1.0, CARD_BORDER);
            w.fg_stroke = Stroke::new(1.0, TXT);
        }
        v.widgets.hovered.corner_radius = CornerRadius::same(6);
        v.widgets.hovered.bg_fill = egui::Color32::from_rgb(36, 36, 50);
        v.widgets.hovered.fg_stroke = Stroke::new(1.0, TXT);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
        v.widgets.active.corner_radius = CornerRadius::same(6);
        v.widgets.active.bg_fill = egui::Color32::from_rgb(0, 110, 70);
        v.widgets.active.fg_stroke = Stroke::new(1.0, ACCENT);
        v.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx.set_style_of(egui::Theme::Dark, style);
        cc.egui_ctx.options_mut(|o| {
            o.theme_preference = egui::ThemePreference::Dark;
        });
        cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(940.0, 800.0)));

        let mut app = Self {
            pid: None,
            handle: None,
            module_name: None,
            module_base: None,
            attached: false,
            status: "game not found".to_string(),
            attach_rx: None,
            attach_started: false,
            cheats: Vec::new(),
            tick_addrs: Vec::new(),
            rx: None,
            busy: None,
            scan_init: 1000.0,
            prev: Vec::new(),
            pointer_results: Vec::new(),
            infinite_enabled: false,
            hook_flag: None,
            key_inf_down: false,
            logs: Vec::new(),
            slogan: "drDOOM69GAMINGS build · v1.0".to_string(),
            bold_family,
        };
        app.log_info("trainer started");
        app
    }

    fn log(&mut self, level: LogLevel, msg: &str) {
        self.logs.push(LogEntry {
            time: now_tag(),
            level,
            msg: msg.to_string(),
        });
        if self.logs.len() > 400 {
            let drop = self.logs.len() - 400;
            self.logs.drain(0..drop);
        }
    }

    fn log_info(&mut self, msg: &str) {
        self.log(LogLevel::Info, msg);
    }

    fn log_good(&mut self, msg: &str) {
        self.log(LogLevel::Good, msg);
    }

    fn log_bad(&mut self, msg: &str) {
        self.log(LogLevel::Bad, msg);
    }

    fn toggle_infinite(&mut self, on: bool) {
        let Some(h) = self.handle else {
            self.log_bad("toggle ignored: not attached");
            return;
        };
        if on {
            if self.hook_flag.is_none() {
                match self.install_infinite_hook() {
                    Ok(_) => {}
                    Err(e) => {
                        self.log_bad(&format!("infinite health hook failed: {e}"));
                        self.infinite_enabled = false;
                        return;
                    }
                }
            }
            if let Some(flag) = self.hook_flag {
                if process::write_bytes(h, flag, &[1u8]) {
                    self.infinite_enabled = true;
                    self.log_good(&format!("infinite health ON · flag byte @0x{flag:X} set to 1"));
                    beep_sequence(1);
                } else {
                    self.log_bad("failed to write enable flag");
                }
            }
        } else {
            if let Some(flag) = self.hook_flag {
                let _ = process::write_bytes(h, flag, &[0u8]);
                self.log_info(&format!("infinite health OFF · flag byte @0x{flag:X} set to 0"));
            }
            self.infinite_enabled = false;
            beep_sequence(3);
        }
    }

    fn poll_hotkeys(&mut self) {
        let down = unsafe {
            (GetAsyncKeyState(VK_NUMPAD1) as i32) & 0x8000 != 0
                || (GetAsyncKeyState(VK_F1) as i32) & 0x8000 != 0
        };
        if down && !self.key_inf_down && self.attached {
            let next = !self.infinite_enabled;
            self.log_info(if next {
                "hotkey (Numpad 1 / F1) → turning infinite health ON"
            } else {
                "hotkey (Numpad 1 / F1) → turning infinite health OFF"
            });
            self.toggle_infinite(next);
        }
        self.key_inf_down = down;
    }

    fn install_infinite_hook(&mut self) -> Result<usize, String> {
        let (Some(h), Some(pid)) = (self.handle, self.pid) else {
            return Err("not attached".to_string());
        };
        self.log_info("install: locating re2.exe module base");
        let mods = process::modules(pid);
        let base = mods
            .iter()
            .find(|(n, _, _)| n.to_lowercase().ends_with("re2.exe"))
            .map(|(_, b, _)| *b)
            .ok_or("re2.exe module base not found")?;
        let fn_addr = base + FN_RVA;
        self.log_info(&format!("install: re2.exe base 0x{base:X} · hook site 0x{fn_addr:X}"));

        const MEM_COMMIT: u32 = 0x1000;
        const MEM_RESERVE: u32 = 0x2000;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const STEP: usize = 0x0100_0000;

        self.log_info("install: allocating stub cave within E9 jump range (±2GB)");
        let mut cave = 0usize;
        let mut hint = fn_addr.wrapping_sub(0x0800_0000);
        while hint > 0x0000_0001_0000_0000 {
            let r = unsafe {
                VirtualAllocEx(
                    h,
                    hint as *mut _,
                    0x200,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                ) as usize
            };
            if r != 0 {
                let rel = (r as i64) - (fn_addr as i64 + 5);
                if rel.unsigned_abs() < (1i64 << 31) as u64 {
                    cave = r;
                    break;
                }
            }
            hint = hint.wrapping_sub(STEP);
        }
        if cave == 0 {
            return Err("no allocateable cave within ±2GB".to_string());
        }
        let code = cave + 0x10;
        let flag = cave;
        self.log_info(&format!(
            "install: cave 0x{cave:X} · stub 0x{code:X} · flag byte @0x{flag:X}"
        ));

        let mut s = Vec::<u8>::with_capacity(64);
        s.extend_from_slice(&[0x48, 0x8B, 0x8E, 0x30, 0x02, 0x00, 0x00]);
        s.extend_from_slice(&[0x48, 0x85, 0xC9]);
        let jz = s.len();
        s.extend_from_slice(&[0x0F, 0x84, 0, 0, 0, 0]);
        let cmp = s.len();
        s.extend_from_slice(&[0x80, 0x3D, 0, 0, 0, 0, 0x01]);
        let jne = s.len();
        s.extend_from_slice(&[0x0F, 0x85, 0, 0, 0, 0]);
        s.extend_from_slice(&[0x50, 0x53]);
        s.extend_from_slice(&[0x48, 0x8D, 0x59, 0x58]);
        s.extend_from_slice(&[0x8B, 0x43, 0xFC]);
        s.extend_from_slice(&[0x89, 0x03]);
        s.extend_from_slice(&[0x5B, 0x58]);
        let cont = s.len();
        s.extend_from_slice(&[0xFF, 0x25, 0, 0, 0, 0]);

        let jz_end = (code + jz + 6) as i64;
        let rel = (code + cont) as i64 - jz_end;
        s[jz + 2..jz + 6].copy_from_slice(&(rel as i32).to_le_bytes());

        let cmp_end = (code + cmp + 7) as i64;
        let disp = flag as i64 - cmp_end;
        s[cmp + 2..cmp + 6].copy_from_slice(&(disp as i32).to_le_bytes());

        let jne_end = (code + jne + 6) as i64;
        let rel2 = (code + cont) as i64 - jne_end;
        s[jne + 2..jne + 6].copy_from_slice(&(rel2 as i32).to_le_bytes());

        s.extend_from_slice(&(fn_addr + 7).to_le_bytes());

        if !process::write_bytes(h, cave, &[0u8]) || !process::write_bytes(h, code, &s) {
            return Err("stub write failed".to_string());
        }
        self.log_info(&format!("install: stub written ({0} bytes)", s.len()));

        let mut old = 0u32;
        let ok_vp = unsafe {
            VirtualProtectEx(h, fn_addr as _, 7, PAGE_EXECUTE_READWRITE, &mut old) != 0
        };
        if !ok_vp {
            return Err("VirtualProtectEx failed".to_string());
        }
        let mut patch = [0u8; 7];
        patch[0] = 0xE9;
        let rel = code as i64 - (fn_addr as i64 + 5);
        patch[1..5].copy_from_slice(&(rel as i32).to_le_bytes());
        patch[5] = 0x90;
        patch[6] = 0x90;
        let ok_w = process::write_bytes(h, fn_addr, &patch);
        let restore = old;
        let _ = unsafe { VirtualProtectEx(h, fn_addr as _, 7, restore, &mut old) };
        if !ok_w {
            return Err("patch write failed".to_string());
        }
        self.hook_flag = Some(flag);
        self.log_good(&format!(
            "install: hook armed · 0x{fn_addr:X} → E9 → 0x{code:X}"
        ));
        Ok(flag)
    }

    fn ensure_attach_worker(&mut self) {
        if self.attached || self.attach_started {
            return;
        }
        let (tx, rx) = channel::<AttachEvent>();
        self.attach_rx = Some(rx);
        self.attach_started = true;
        std::thread::spawn(move || attach_worker(tx));
    }

    fn pump_attach(&mut self) {
        let events: Vec<AttachEvent> = match &self.attach_rx {
            Some(rx) => {
                let mut v = Vec::new();
                while let Ok(e) = rx.try_recv() {
                    v.push(e);
                }
                v
            }
            None => return,
        };
        for ev in events {
            match ev {
                AttachEvent::Found { pid, handle, module } => {
                    self.pid = Some(pid);
                    self.handle = Some(handle);
                    match module {
                        Some((name, base)) => {
                            let msg = format!("attached · pid {pid} · module {name} @0x{base:X}");
                            self.module_name = Some(name);
                            self.module_base = Some(base);
                            self.attached = true;
                            self.status = "attached".to_string();
                            self.log_good(&msg);
                        }
                        None => {
                            self.attached = true;
                            self.status = "attached (no module base)".to_string();
                            self.log_good(&format!("attached · pid {pid} (no module base found)"));
                        }
                    }
                }
            }
        }
    }

    fn detach(&mut self) {
        if let Some(h) = self.handle.take() {
            process::close_process(h);
        }
        self.pid = None;
        self.module_name = None;
        self.module_base = None;
        self.attached = false;
        self.infinite_enabled = false;
        self.hook_flag = None;
        self.key_inf_down = false;
        for a in &mut self.tick_addrs {
            *a = 0;
        }
        self.prev.clear();
        self.pointer_results.clear();
        self.attach_started = false;
        self.log_info("detached · ready to attach on next game launch");
    }

    fn pump(&mut self) {
        let events: Vec<ScanEvent> = match &self.rx {
            Some(rx) => {
                let mut v = Vec::new();
                while let Ok(e) = rx.try_recv() {
                    v.push(e);
                }
                v
            }
            None => return,
        };
        for ev in events {
            match ev {
                ScanEvent::Initial(v) => {
                    self.prev = v;
                    self.busy = None;
                    self.log_info(&format!("scan: new scan done → {} candidates", self.prev.len()));
                }
                ScanEvent::Sub(v) => {
                    self.prev = v;
                    self.busy = None;
                    self.log_info(&format!("scan: pass done → {} candidates", self.prev.len()));
                }
                ScanEvent::Pointer(v) => {
                    self.pointer_results = v;
                    self.busy = None;
                    self.log_info(&format!(
                        "scan: {} stable pointers found",
                        self.pointer_results.len()
                    ));
                }
            }
        }
    }

    fn spawn<F>(&mut self, label: &str, f: F)
    where
        F: FnOnce(std::sync::mpsc::Sender<ScanEvent>) + Send + 'static,
    {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        self.busy = Some(label.to_string());
        std::thread::spawn(move || {
            f(tx);
        });
    }

    fn add_cheat(&mut self, label: &str, offsets: Vec<isize>, absolute: bool) {
        self.cheats.push(Cheat {
            label: label.to_string(),
            offsets,
            absolute,
            target: CheatValue::Float(1000.0),
            enabled: true,
        });
        self.tick_addrs.push(0);
        self.log_info(&format!("cheat added: {label}"));
    }

    fn apply_cheats(&mut self) {
        let (Some(h), Some(base)) = (self.handle, self.module_base) else {
            return;
        };
        for (i, cheat) in self.cheats.iter().enumerate() {
            if !cheat.enabled {
                continue;
            }
            if !cheat.apply(h, base, &mut self.tick_addrs[i]) {
                self.log_bad(&format!("cheat lost its target ({}) · detaching", cheat.label));
                self.detach();
                return;
            }
        }
    }

    fn value_of(&self, i: usize) -> Option<f32> {
        let (Some(h), Some(base)) = (self.handle, self.module_base) else {
            return None;
        };
        let cheat = &self.cheats[i];
        if self.tick_addrs[i] != 0 {
            unsafe { process::read_memory::<f32>(h, self.tick_addrs[i]) }
        } else {
            let addr = cheat.resolve_here(h, base)?;
            unsafe { process::read_memory::<f32>(h, addr) }
        }
    }

    fn card(ui: &mut Ui, body: impl FnOnce(&mut Ui)) {
        egui::Frame::new()
            .fill(CARD)
            .stroke(Stroke::new(1.0, CARD_BORDER))
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::same(14))
            .show(ui, body);
    }

    fn section_title(ui: &mut Ui, text: &str, accent: egui::Color32) {
        ui.label(
            RichText::new(text.to_uppercase())
                .size(11.5)
                .strong()
                .color(accent),
        );
        ui.add_space(4.0);
    }
}

enum Action {
    NewScan(f32),
    Pass(ScanPass),
    Freeze(usize),
    PtrScan(usize),
    SetPointer(PointerCandidate),
    Remove(usize),
    ToggleInfinite(bool),
}

fn beep_sequence(count: u32) {
    std::thread::spawn(move || {
        for i in 0..count {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(90));
            }
            unsafe {
                Beep(1200, 120);
            }
        }
    });
}

impl eframe::App for TrainerApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        ui.ctx().request_repaint_after(Duration::from_millis(50));

        self.ensure_attach_worker();
        self.pump_attach();
        self.pump();
        self.poll_hotkeys();
        if self.attached {
            self.apply_cheats();
        }

        let mut action: Option<Action> = None;

        ui.add_space(6.0);
        Self::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("RE2 BIO2 TRAINER 2026 PC STEAM")
                        .size(24.0)
                        .strong()
                        .color(TXT)
                        .family(self.bold_family.clone()),
                );
                ui.label(RichText::new(&self.slogan).size(12.5).color(PINK));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.attached {
                        ui.colored_label(ACCENT, "● attached");
                        if ui.small_button("detach").clicked() {
                            self.detach();
                        }
                    } else {
                        ui.colored_label(BAD, "● waiting for game…");
                    }
                });
            });
        });
        ui.add_space(8.0);

        if !self.attached {
            Self::card(ui, |ui| {
                ui.label(
                    RichText::new("Launch Resident Evil 2 and the trainer will attach automatically.")
                        .color(MUTED),
                );
            });
            ui.add_space(8.0);
            self.log_ui(ui);
            if let Some(a) = action {
                self.dispatch(a);
            }
            return;
        }

        Self::card(ui, |ui| {
            Self::section_title(ui, "Cheats", ACCENT);
            let on = self.infinite_enabled;
            let a: &mut Option<Action> = &mut action;
            let btn = egui::Button::new(
                RichText::new(if on {
                    "▶ INFINITE HEALTH - ON"
                } else {
                    "▶ INFINITE HEALTH - OFF"
                })
                .strong()
                .size(16.0)
                .color(if on {
                    egui::Color32::from_rgb(6, 40, 26)
                } else {
                    TXT
                }),
            )
            .fill(if on { ACCENT } else { INACTIVE_BG })
            .stroke(Stroke::new(1.0, if on { ACCENT } else { PINK }))
            .corner_radius(CornerRadius::same(8))
            .min_size(egui::vec2(0.0, 44.0));
            if ui.add_sized([ui.available_width(), 44.0], btn).clicked() {
                *a = Some(Action::ToggleInfinite(!on));
            }
            ui.label(
                RichText::new("hotkeys: Numpad 1 or F1 · ding = ON · triple ding = OFF")
                    .size(12.0)
                    .color(MUTED),
            );
            if !self.cheats.is_empty() {
                ui.add_space(6.0);
                ui.separator();
                let values: Vec<Option<f32>> = (0..self.cheats.len()).map(|i| self.value_of(i)).collect();
                let mut clicked_remove: Option<usize> = None;
                for (i, cheat) in self.cheats.iter_mut().enumerate() {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut cheat.enabled, &cheat.label);
                        ui.label(
                            RichText::new(match values[i] {
                                Some(v) => format!("{v:.0}"),
                                None => "--".to_string(),
                            })
                            .color(MUTED),
                        );
                        if ui.small_button("x").clicked() {
                            clicked_remove = Some(i);
                        }
                    });
                    if let Some(i) = clicked_remove {
                        *a = Some(Action::Remove(i));
                    }
                }
            }
        });
        ui.add_space(8.0);

        self.scan_ui(ui, &mut action);
        self.pointer_ui(ui, &mut action);
        ui.add_space(8.0);
        self.log_ui(ui);

        if let Some(action) = action {
            self.dispatch(action);
        }
    }
}

impl TrainerApp {
    fn log_ui(&mut self, ui: &mut Ui) {
        Self::card(ui, |ui| {
            Self::section_title(ui, "Activity log", PINK);
            egui::ScrollArea::vertical()
                .max_height(230.0)
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for e in &self.logs {
                        let color = match e.level {
                            LogLevel::Good => ACCENT,
                            LogLevel::Info => MUTED,
                            LogLevel::Bad => BAD,
                        };
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(&e.time).monospace().size(11.0).color(CARD_BORDER),
                            );
                            ui.label(RichText::new("·").color(egui::Color32::from_rgb(255, 46, 136)));
                            ui.label(RichText::new(&e.msg).color(color).size(12.5));
                        });
                    }
                });
        });
    }

    fn scan_ui(&mut self, ui: &mut Ui, action: &mut Option<Action>) {
        Self::card(ui, |ui| {
            Self::section_title(ui, "Memory Scan (float)", ACCENT);
            ui.horizontal(|ui| {
                ui.label(RichText::new("value:").color(MUTED));
                ui.add(egui::DragValue::new(&mut self.scan_init).speed(1.0));
                if ui.button("new scan").clicked() {
                    self.log_info(&format!("scan: starting new scan for {:.1}", self.scan_init));
                    *action = Some(Action::NewScan(self.scan_init));
                }
                if !self.prev.is_empty() {
                    if ui.button("decreased").clicked() {
                        *action = Some(Action::Pass(ScanPass::Decreased));
                    }
                    if ui.button("increased").clicked() {
                        *action = Some(Action::Pass(ScanPass::Increased));
                    }
                    if ui.button("changed").clicked() {
                        *action = Some(Action::Pass(ScanPass::Changed));
                    }
                    if ui.button("unchanged").clicked() {
                        *action = Some(Action::Pass(ScanPass::Unchanged));
                    }
                }
            });

            if let Some(b) = &self.busy {
                ui.label(RichText::new(b.as_str()).color(egui::Color32::from_rgb(255, 199, 102)));
            }

            let count = self.prev.len();
            ui.label(
                RichText::new(format!(
                    "{count} candidates{}",
                    if count > MAX_ROWS { " (showing first 200)" } else { "" }
                ))
                .color(MUTED),
            );

            if self.prev.is_empty() {
                return;
            }
            let rows: Vec<(usize, f32)> = self.prev.iter().take(MAX_ROWS).cloned().collect();
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (addr, val) in &rows {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("0x{addr:X}"));
                            ui.label(format!("{val:.2}"));
                            if ui.small_button("freeze 1000").clicked() {
                                *action = Some(Action::Freeze(*addr));
                            }
                            if ui.small_button("stable ptr").clicked() {
                                *action = Some(Action::PtrScan(*addr));
                            }
                        });
                    }
                });
        });
    }

    fn pointer_ui(&mut self, ui: &mut Ui, action: &mut Option<Action>) {
        if self.pointer_results.is_empty() {
            return;
        }
        ui.add_space(8.0);
        Self::card(ui, |ui| {
            Self::section_title(ui, "Stable pointers", ACCENT);
            let rows: Vec<PointerCandidate> = self.pointer_results.iter().take(MAX_ROWS).cloned().collect();
            egui::ScrollArea::vertical()
                .max_height(150.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for c in &rows {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{}+{:X}", c.module, c.rel_offset));
                            ui.label(format!("+{:+X}", c.delta));
                            if ui.small_button("set cheat").clicked() {
                                *action = Some(Action::SetPointer(c.clone()));
                            }
                        });
                    }
                });
        });
    }

    fn dispatch(&mut self, action: Action) {
        let Some(h) = self.handle else { return };
        match action {
            Action::NewScan(val) => {
                self.prev.clear();
                self.pointer_results.clear();
                let h = h;
                self.spawn("scanning for exact value", move |tx| {
                    scanner::run_initial(h, val, tx);
                });
            }
            Action::Pass(pass) => {
                let (h, prev) = (h, self.prev.clone());
                self.spawn("scanning pass...", move |tx| {
                    scanner::run_sub(h, prev, pass, tx);
                });
            }
            Action::Freeze(addr) => {
                self.add_cheat("HP freeze (session)", vec![addr as isize], true);
            }
            Action::PtrScan(addr) => {
                let target = addr;
                let module = self
                    .module_name
                    .clone()
                    .unwrap_or_else(|| "re_chunk_0000000000000000000000000.exe".to_string());
                let pid = self.pid.unwrap_or(0);
                self.pointer_results.clear();
                let h = h;
                self.spawn("scanning for stable pointers...", move |tx| {
                    scanner::run_pointer(h, pid, target, module, tx);
                });
            }
            Action::SetPointer(c) => {
                let mut offsets = vec![c.rel_offset as isize, c.delta];
                if c.delta == 0 {
                    offsets.pop();
                }
                self.add_cheat("Infinite Health (stable)", offsets, false);
            }
            Action::Remove(i) => {
                if i < self.cheats.len() {
                    let removed = self.cheats.remove(i);
                    self.tick_addrs.remove(i);
                    self.log_info(&format!("cheat removed: {}", removed.label));
                }
            }
            Action::ToggleInfinite(on) => {
                self.toggle_infinite(on);
            }
        }
    }
}