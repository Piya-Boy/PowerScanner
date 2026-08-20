use eframe::egui::{self, Color32, FontId, Pos2, Stroke, Vec2};

/// Draw a circular progress ring with a percentage and phase label.
pub fn circular_progress(ui: &mut egui::Ui, fraction: f32, label: &str) {
    let fraction = fraction.clamp(0.0, 1.0);
    let diameter = 150.0_f32;
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(diameter), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let center = rect.center();
    let radius = diameter / 2.0 - 8.0;
    let stroke_width = 11.0_f32;
    let track = ui.visuals().widgets.inactive.bg_fill;
    let accent = ui.visuals().selection.bg_fill;

    painter.circle_stroke(center, radius, Stroke::new(stroke_width, track));

    if fraction > 0.0 {
        let start = -std::f32::consts::FRAC_PI_2;
        let sweep = fraction * std::f32::consts::TAU;
        let steps = (sweep / 0.05).ceil().max(2.0) as usize;
        let points: Vec<Pos2> = (0..=steps)
            .map(|index| {
                let angle = start + sweep * (index as f32 / steps as f32);
                Pos2::new(
                    center.x + radius * angle.cos(),
                    center.y + radius * angle.sin(),
                )
            })
            .collect();
        painter.add(egui::Shape::line(points, Stroke::new(stroke_width, accent)));
    }

    painter.text(
        center - Vec2::new(0.0, 6.0),
        egui::Align2::CENTER_CENTER,
        format!("{}%", (fraction * 100.0).round() as i32),
        FontId::proportional(30.0),
        ui.visuals().text_color(),
    );
    painter.text(
        center + Vec2::new(0.0, 20.0),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::proportional(11.0),
        Color32::from_gray(140),
    );
}
