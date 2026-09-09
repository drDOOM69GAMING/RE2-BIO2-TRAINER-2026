#![cfg_attr(not(feature = "cli"), windows_subsystem = "windows")]

mod app;
mod cheat;
mod cli;
mod process;
mod scanner;

use app::TrainerApp;
use eframe::egui;

fn boot_log(step: &str) {
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(std::env::temp_dir().join("re2boot.txt"))
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(format!("{step}\n").as_bytes())
        });
}

fn main() -> eframe::Result {
    boot_log("main start");
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--cli") {
        std::process::exit(cli::run(&args[1..]));
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(egui::vec2(520.0, 380.0))
            .with_min_inner_size(egui::vec2(420.0, 300.0)),
        ..Default::default()
    };
    boot_log("creating native window");
    let res = eframe::run_native(
        "RE2 BIO2 TRAINER 2026 PC STEAM",
        options,
        Box::new(|cc| Ok(Box::new(TrainerApp::new(cc)))),
    );
    boot_log(&format!("run_native returned: {res:?}"));
    res
}