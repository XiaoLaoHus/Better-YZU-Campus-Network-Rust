use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, FontId, Margin, RichText, Stroke, TextStyle};

pub const BACKGROUND: Color32 = Color32::from_rgb(245, 246, 250);
pub const CARD: Color32 = Color32::WHITE;
pub const ACCENT: Color32 = Color32::from_rgb(36, 91, 196);
pub const MUTED: Color32 = Color32::from_rgb(99, 110, 129);

pub fn setup(ctx: &egui::Context) -> Result<(), String> {
    let root = std::env::var_os("WINDIR").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "C:/Windows".into()).join("Fonts");
    let mut fonts = FontDefinitions::default();
    let bytes = ["msyh.ttc", "msyh.ttf", "simhei.ttf", "simsun.ttc", "NotoSansSC.ttf"]
        .iter().find_map(|name| std::fs::read(root.join(name)).ok())
        .ok_or("未找到可用中文字体（微软雅黑、黑体或宋体），请检查 Windows 字体安装。")?;
    fonts.font_data.insert("chinese".into(), FontData::from_owned(bytes).into());
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts.families.get_mut(&family).unwrap().insert(0, "chinese".into());
    }
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::light();
    style.visuals.panel_fill = BACKGROUND;
    style.visuals.window_fill = CARD;
    style.visuals.extreme_bg_color = Color32::from_rgb(248, 250, 253);
    style.visuals.override_text_color = Some(Color32::from_rgb(38, 47, 65));
    style.visuals.selection.bg_fill = Color32::from_rgb(206, 223, 255);
    for widget in [&mut style.visuals.widgets.inactive, &mut style.visuals.widgets.hovered, &mut style.visuals.widgets.active] {
        widget.corner_radius = 8.into();
    }
    style.spacing.item_spacing = egui::vec2(12.0, 10.0);
    style.spacing.button_padding = egui::vec2(16.0, 9.0);
    style.spacing.interact_size.y = 42.0;
    style.text_styles.insert(TextStyle::Body, FontId::proportional(15.0));
    style.text_styles.insert(TextStyle::Button, FontId::proportional(15.0));
    style.text_styles.insert(TextStyle::Heading, FontId::proportional(26.0));
    style.text_styles.insert(TextStyle::Small, FontId::proportional(12.0));
    ctx.set_style(style);
    Ok(())
}

pub fn card() -> egui::Frame {
    egui::Frame::new().fill(CARD).corner_radius(14).inner_margin(Margin::same(20))
        .stroke(Stroke::new(1.0, Color32::from_rgb(230, 234, 242)))
}

pub fn primary(text: &str) -> egui::Button<'_> {
    egui::Button::new(RichText::new(text).color(Color32::WHITE)).fill(ACCENT)
}

pub fn input<'a>(text: &'a mut String, id: &str, password: bool) -> egui::TextEdit<'a> {
    egui::TextEdit::singleline(text).id(egui::Id::new(id)).password(password)
        .horizontal_align(egui::Align::Center).vertical_align(egui::Align::Center)
        .margin(Margin::symmetric(12, 8)).min_size(egui::vec2(0.0, 42.0))
        .desired_width(f32::INFINITY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_text_is_centered_at_each_scale() {
        for scale in [1.0, 1.5, 2.0] {
            for password in [false, true] {
                let ctx = egui::Context::default();
                ctx.set_pixels_per_point(scale);
                let mut text = "123456789".to_owned();
                // Warm up font/layout state before checking the final geometry.
                for _ in 0..2 {
                    let _ = ctx.run(egui::RawInput::default(), |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.set_width(320.0);
                            let output = input(&mut text, "center-test", password).show(ui);
                            let text_center = output.galley_pos + output.galley.size() / 2.0;
                            let center = output.response.rect.center();
                            assert!((text_center.x - center.x).abs() <= 1.0, "horizontal centering at {scale}x");
                            assert!((text_center.y - center.y).abs() <= 1.0, "vertical centering at {scale}x");
                            assert!(output.response.rect.height() >= 42.0);
                            if password { assert!(!output.galley.text().contains("123456789")); }
                        });
                    });
                }
            }
        }
    }
}
