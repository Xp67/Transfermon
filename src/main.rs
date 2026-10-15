#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod theme;
mod ui;

fn main() -> eframe::Result<()> {
    transfermon::sysinfo::install_panic_hook();
    // `transfermon sender` / `transfermon receiver` aprono subito quella schermata.
    let start = std::env::args().nth(1);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 720.0])
            .with_min_inner_size([780.0, 540.0])
            .with_title("Transfermon"),
        ..Default::default()
    };
    eframe::run_native(
        "Transfermon",
        options,
        Box::new(move |cc| Ok(Box::new(ui::App::new(cc, start)))),
    )
}
