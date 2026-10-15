//! Aspetto di Transfermon: un foglio bianco su carta grigio-azzurra.
//!
//! - Un solo colore d'azione (petrolio) per pulsanti principali, selezioni e
//!   avanzamento; verde per il completato, rosso per gli errori. Il resto è
//!   inchiostro su bianco.
//! - Niente ombre, gradienti o decorazioni: la gerarchia la fanno dimensione e
//!   peso del carattere; le righe separano le sezioni; i numeri stanno in colonna.
//! - Segoe UI (Semibold per titoli e codice, Regular per il testo, Bold per le
//!   enfasi) e Cascadia Mono per i percorsi, presi dai font di Windows; se
//!   mancano si usano i font di egui.

use std::path::PathBuf;
use std::sync::Arc;

use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};
use egui::{
    Align2, Color32, Context, CornerRadius, FontData, FontFamily, FontId, Galley, Margin, Painter,
    Rangef, Rect, Response, RichText, Sense, Stroke, StrokeKind, TextStyle, TextWrapMode, Ui, Vec2,
    Visuals, WidgetText,
};

pub const PAPER: Color32 = Color32::from_rgb(0xee, 0xf1, 0xf5);
pub const SURFACE: Color32 = Color32::WHITE;
pub const INK: Color32 = Color32::from_rgb(0x1c, 0x27, 0x33);
pub const MUTED: Color32 = Color32::from_rgb(0x5e, 0x6b, 0x78);
pub const LINE: Color32 = Color32::from_rgb(0xd5, 0xdc, 0xe4);
pub const LINE_STRONG: Color32 = Color32::from_rgb(0xb9, 0xc4, 0xce);
pub const PRIMARY: Color32 = Color32::from_rgb(0x0f, 0x6f, 0x8f);
pub const PRIMARY_HOVER: Color32 = Color32::from_rgb(0x0b, 0x5a, 0x75);
pub const PRIMARY_DOWN: Color32 = Color32::from_rgb(0x09, 0x4a, 0x60);
pub const PRIMARY_TINT: Color32 = Color32::from_rgb(0xe9, 0xf3, 0xf6);
pub const TRACK: Color32 = Color32::from_rgb(0xe3, 0xe8, 0xee);
pub const OK: Color32 = Color32::from_rgb(0x1e, 0x8a, 0x5b);
pub const ERR: Color32 = Color32::from_rgb(0xb3, 0x26, 0x1e);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Pieno, petrolio, testo bianco: l'azione principale della schermata.
    Primary,
    /// Bianco con bordo: tutte le altre azioni.
    Secondary,
}

pub struct Theme {
    pub display: FontFamily,
    pub bold: FontFamily,
    pub mono: FontFamily,
}

impl Theme {
    pub fn install(ctx: &Context) -> Theme {
        let theme = install_fonts(ctx);
        let display = theme.display.clone();
        let mono = theme.mono.clone();
        ctx.all_styles_mut(|s| {
            s.text_styles.insert(TextStyle::Heading, FontId::new(24.0, display.clone()));
            s.text_styles.insert(TextStyle::Body, FontId::new(15.0, FontFamily::Proportional));
            s.text_styles.insert(TextStyle::Button, FontId::new(15.0, FontFamily::Proportional));
            s.text_styles.insert(TextStyle::Small, FontId::new(12.5, FontFamily::Proportional));
            s.text_styles.insert(TextStyle::Monospace, FontId::new(13.0, mono.clone()));
            s.spacing.item_spacing = egui::vec2(8.0, 8.0);
            s.spacing.button_padding = egui::vec2(14.0, 7.0);
            s.spacing.interact_size.y = 24.0;
            s.visuals = visuals();
        });
        ctx.set_theme(egui::Theme::Light);
        theme
    }

    /// Testo in Semibold (titoli, numeri in evidenza).
    pub fn display(&self, text: impl Into<String>, size: f32) -> RichText {
        RichText::new(text).family(self.display.clone()).size(size)
    }

    /// Testo in grassetto (egui non sintetizza il bold: serve un font a parte).
    pub fn bold(&self, text: impl Into<String>) -> RichText {
        RichText::new(text).family(self.bold.clone())
    }

    /// Percorsi e altri dati "letterali", in monospazio attenuato.
    pub fn mono(&self, text: impl Into<String>) -> RichText {
        RichText::new(text).family(self.mono.clone()).size(12.5).color(MUTED)
    }
}

// ----- font -----

fn system_font(file: &str) -> Option<FontData> {
    let dir = std::env::var("WINDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows"))
        .join("Fonts");
    let bytes = std::fs::read(dir.join(file)).ok()?;
    // egui va in panic su un font non valido: lo si verifica prima.
    ab_glyph::FontArc::try_from_vec(bytes.clone()).ok()?;
    Some(FontData::from_owned(bytes))
}

fn add_font(ctx: &Context, name: &str, data: FontData, families: &[FontFamily]) {
    ctx.add_font(FontInsert {
        name: name.to_string(),
        data,
        families: families
            .iter()
            .map(|f| InsertFontFamily {
                family: f.clone(),
                priority: FontPriority::Highest,
            })
            .collect(),
    });
}

fn install_fonts(ctx: &Context) -> Theme {
    let display = FontFamily::Name(Arc::from("display"));
    let bold = FontFamily::Name(Arc::from("bold"));
    let mono = FontFamily::Name(Arc::from("mono"));
    let mut theme = Theme {
        display: FontFamily::Proportional,
        bold: FontFamily::Proportional,
        mono: FontFamily::Monospace,
    };
    if let Some(d) = system_font("segoeui.ttf") {
        add_font(ctx, "body", d, &[FontFamily::Proportional]);
    }
    if let Some(d) = system_font("seguisb.ttf") {
        add_font(ctx, "display", d, std::slice::from_ref(&display));
        theme.display = display;
    }
    if let Some(d) = system_font("segoeuib.ttf") {
        add_font(ctx, "bold", d, std::slice::from_ref(&bold));
        theme.bold = bold;
    }
    if let Some(d) = system_font("CascadiaMono.ttf").or_else(|| system_font("consola.ttf")) {
        add_font(ctx, "mono", d, &[mono.clone(), FontFamily::Monospace]);
        theme.mono = mono;
    }
    theme
}

// ----- visuals per i widget standard (checkbox, radio, campi, scroll, tooltip) -----

fn visuals() -> Visuals {
    let mut v = Visuals::light();
    v.override_text_color = Some(INK);
    v.weak_text_color = Some(MUTED);
    v.panel_fill = PAPER;
    v.window_fill = SURFACE;
    v.window_stroke = Stroke::new(1.0, LINE);
    v.window_corner_radius = CornerRadius::same(8);
    v.extreme_bg_color = SURFACE;
    v.faint_bg_color = Color32::from_rgb(0xf5, 0xf7, 0xfa);
    v.code_bg_color = PAPER;
    v.hyperlink_color = PRIMARY;
    v.warn_fg_color = Color32::from_rgb(0x9a, 0x6b, 0x00);
    v.error_fg_color = ERR;
    v.selection.bg_fill = Color32::from_rgba_unmultiplied(15, 111, 143, 70);
    v.selection.stroke = Stroke::new(1.0, PRIMARY);
    v.striped = true;

    v.widgets.noninteractive.bg_fill = Color32::TRANSPARENT;
    v.widgets.noninteractive.weak_bg_fill = Color32::TRANSPARENT;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, LINE);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, INK);

    v.widgets.inactive.bg_fill = SURFACE;
    v.widgets.inactive.weak_bg_fill = SURFACE;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, LINE_STRONG);
    v.widgets.inactive.fg_stroke = Stroke::new(1.5, INK);
    v.widgets.inactive.corner_radius = CornerRadius::same(5);

    v.widgets.hovered.bg_fill = Color32::from_rgb(0xf3, 0xf6, 0xf9);
    v.widgets.hovered.weak_bg_fill = Color32::from_rgb(0xf3, 0xf6, 0xf9);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, PRIMARY);
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, PRIMARY);
    v.widgets.hovered.corner_radius = CornerRadius::same(5);

    v.widgets.active.bg_fill = PRIMARY_TINT;
    v.widgets.active.weak_bg_fill = PRIMARY_TINT;
    v.widgets.active.bg_stroke = Stroke::new(1.0, PRIMARY);
    v.widgets.active.fg_stroke = Stroke::new(2.0, PRIMARY);
    v.widgets.active.corner_radius = CornerRadius::same(5);

    v.widgets.open = v.widgets.hovered;
    v
}

// ----- widget -----

pub fn button(ui: &mut Ui, theme: &Theme, text: impl Into<RichText>, kind: Kind) -> Response {
    button_sized(ui, theme, text, kind, Vec2::ZERO)
}

pub fn button_sized(
    ui: &mut Ui,
    theme: &Theme,
    text: impl Into<RichText>,
    kind: Kind,
    min: Vec2,
) -> Response {
    let _ = theme;
    let text: RichText = text.into();
    let enabled = ui.is_enabled();
    let color = match kind {
        Kind::Primary => Color32::WHITE,
        Kind::Secondary => {
            if enabled {
                INK
            } else {
                MUTED
            }
        }
    };
    // Il colore va messo nel testo: `override_text_color` vince sul colore di
    // ripiego passato a `painter.galley`.
    let galley = WidgetText::from(text.color(color)).into_galley(
        ui,
        Some(TextWrapMode::Extend),
        f32::INFINITY,
        TextStyle::Button,
    );
    let padding = egui::vec2(18.0, 9.0);
    let size = (galley.size() + 2.0 * padding).max(min);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = enabled && resp.hovered();
        let down = enabled && resp.is_pointer_button_down_on();
        let p = ui.painter();
        match kind {
            Kind::Primary => {
                let fill = if !enabled {
                    LINE_STRONG
                } else if down {
                    PRIMARY_DOWN
                } else if hovered {
                    PRIMARY_HOVER
                } else {
                    PRIMARY
                };
                p.rect_filled(rect, CornerRadius::same(6), fill);
            }
            Kind::Secondary => {
                let fill = if down {
                    Color32::from_rgb(0xe6, 0xeb, 0xf0)
                } else if hovered {
                    Color32::from_rgb(0xf3, 0xf6, 0xf9)
                } else {
                    SURFACE
                };
                p.rect_filled(rect, CornerRadius::same(6), fill);
                let line = if hovered { Color32::from_rgb(0x8a, 0x98, 0xa6) } else { LINE_STRONG };
                p.rect_stroke(rect, CornerRadius::same(6), Stroke::new(1.0, line), StrokeKind::Inside);
            }
        }
        p.galley(rect.center() - galley.size() / 2.0, galley, color);
    }
    resp
}

/// Scelta grande con titolo e descrizione (le due porte della schermata iniziale).
pub fn tile(ui: &mut Ui, theme: &Theme, title: &str, subtitle: &str) -> Response {
    let size = egui::vec2(ui.available_width().min(390.0), 118.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    if ui.is_rect_visible(rect) {
        let hovered = resp.hovered();
        let p = ui.painter();
        p.rect_filled(
            rect,
            CornerRadius::same(10),
            if hovered { PRIMARY_TINT } else { SURFACE },
        );
        p.rect_stroke(
            rect,
            CornerRadius::same(10),
            Stroke::new(1.5, if hovered { PRIMARY } else { LINE_STRONG }),
            StrokeKind::Inside,
        );
        let title_galley = p.layout_no_wrap(
            title.to_string(),
            FontId::new(24.0, theme.display.clone()),
            INK,
        );
        let sub_galley = p.layout(
            subtitle.to_string(),
            FontId::new(15.0, FontFamily::Proportional),
            MUTED,
            rect.width() - 48.0,
        );
        let x = rect.left() + 24.0;
        p.galley(egui::pos2(x, rect.top() + 24.0), title_galley, INK);
        p.galley(egui::pos2(x, rect.top() + 62.0), sub_galley, MUTED);
    }
    resp
}

/// Il foglio bianco che contiene la schermata.
pub fn sheet<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, LINE))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(32, 28))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

/// Riga sottile che separa due sezioni del foglio.
pub fn rule(ui: &mut Ui) {
    ui.add_space(16.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter()
        .hline(rect.x_range(), rect.center().y, Stroke::new(1.0, LINE));
    ui.add_space(16.0);
}

/// Titolo di un passo: numero nel cerchio e testo.
pub fn step_title(ui: &mut Ui, theme: &Theme, number: &str, text: &str) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(26.0, 26.0), Sense::hover());
        ui.painter().circle_filled(rect.center(), 13.0, PRIMARY);
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            number,
            FontId::new(13.5, theme.bold.clone()),
            Color32::WHITE,
        );
        ui.add_space(2.0);
        ui.label(theme.display(text, 19.0));
    });
    ui.add_space(4.0);
}

/// Codice di collegamento in grande, cifra per cifra, su un riquadro di carta.
pub fn pin_block(ui: &mut Ui, theme: &Theme, pin: &str) {
    egui::Frame::new()
        .fill(PAPER)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(24, 22))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.vertical_centered(|ui| {
                ui.label(RichText::new("Codice di collegamento").color(MUTED));
                ui.add_space(2.0);
                let font = FontId::new(72.0, theme.display.clone());
                let galleys: Vec<Arc<Galley>> = pin
                    .chars()
                    .map(|c| ui.painter().layout_no_wrap(c.to_string(), font.clone(), INK))
                    .collect();
                let gap = 2.0;
                let group_gap = 30.0;
                let total: f32 = galleys.iter().map(|g| g.size().x + 4.0).sum::<f32>()
                    + gap * galleys.len().saturating_sub(1) as f32
                    + if galleys.len() > 3 { group_gap } else { 0.0 };
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = gap;
                    ui.add_space(((ui.available_width() - total) / 2.0).max(0.0));
                    for (i, galley) in galleys.into_iter().enumerate() {
                        if i == 3 {
                            ui.add_space(group_gap);
                        }
                        let (rect, _) = ui.allocate_exact_size(
                            galley.size() + egui::vec2(4.0, 0.0),
                            Sense::hover(),
                        );
                        ui.painter()
                            .galley(rect.min + egui::vec2(2.0, 0.0), galley, INK);
                    }
                });
            });
        });
}

/// Barra di avanzamento: traccia chiara, riempimento petrolio.
pub fn progress(ui: &mut Ui, frac: f32) {
    let h = 12.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), h), Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(6), TRACK);
    let frac = frac.clamp(0.0, 1.0);
    if frac > 0.0 {
        let w = (rect.width() * frac).max(h);
        p.rect_filled(
            Rect::from_min_size(rect.min, egui::vec2(w, h)),
            CornerRadius::same(6),
            PRIMARY,
        );
    }
}

/// Icona "?" con spiegazione al passaggio del mouse.
pub fn help(ui: &mut Ui, theme: &Theme, text: &str) {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), Sense::hover());
    let p = ui.painter();
    let color = if resp.hovered() { PRIMARY } else { LINE_STRONG };
    p.circle_stroke(rect.center(), 8.0, Stroke::new(1.0, color));
    p.text(
        rect.center(),
        Align2::CENTER_CENTER,
        "?",
        FontId::new(12.0, theme.bold.clone()),
        if resp.hovered() { PRIMARY } else { MUTED },
    );
    resp.on_hover_text(text);
}

/// Pallino di stato.
pub fn dot(ui: &mut Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.5, color);
}

/// Riga "attendi" con spinner e testo; `centered` la centra nella larghezza.
pub fn wait_line(ui: &mut Ui, text: &str, centered: bool) {
    let galley = ui.painter().layout_no_wrap(
        text.to_string(),
        TextStyle::Body.resolve(ui.style()),
        INK,
    );
    let spinner = 18.0;
    let total = spinner + ui.spacing().item_spacing.x + galley.size().x;
    ui.horizontal(|ui| {
        if centered {
            ui.add_space(((ui.available_width() - total) / 2.0).max(0.0));
        }
        ui.add(egui::Spinner::new().size(spinner).color(PRIMARY));
        ui.label(text);
    });
}

// ----- sfondo e cornice -----

pub fn paint_background(painter: &Painter, rect: Rect) {
    painter.rect_filled(rect, CornerRadius::ZERO, PAPER);
}

pub fn paint_header(painter: &Painter, rect: Rect) {
    painter.rect_filled(rect, CornerRadius::ZERO, PAPER);
    painter.hline(
        Rangef::new(rect.left(), rect.right()),
        rect.bottom() - 0.5,
        Stroke::new(1.0, LINE),
    );
}

pub fn paint_footer(painter: &Painter, rect: Rect) {
    painter.rect_filled(rect, CornerRadius::ZERO, SURFACE);
    painter.hline(
        Rangef::new(rect.left(), rect.right()),
        rect.top() + 0.5,
        Stroke::new(1.0, LINE),
    );
}
