pub(crate) const HIGH_RISK: &str = "【高危】";
pub(crate) const DANGER: &str = "【危险】";
pub(crate) const WARNING: &str = "【警告】";
pub(crate) const NORMAL: &str = "【正常】";

pub(crate) fn is_issue(label: &str) -> bool {
    matches!(label, HIGH_RISK | DANGER | WARNING)
}

pub(crate) fn is_normal(label: &str) -> bool {
    label == NORMAL
}

pub(crate) fn rank(label: &str) -> u8 {
    match label {
        HIGH_RISK => 4,
        DANGER => 3,
        WARNING => 2,
        NORMAL => 1,
        _ => 0,
    }
}

pub(crate) fn max_label<'a>(labels: impl IntoIterator<Item = &'a str>) -> &'static str {
    let mut best = NORMAL;
    for label in labels {
        if rank(label) > rank(best) {
            best = match label {
                HIGH_RISK => HIGH_RISK,
                DANGER => DANGER,
                WARNING => WARNING,
                NORMAL => NORMAL,
                _ => best,
            };
        }
    }
    best
}
