//! Small word list for human-typeable pairing codes (Magic Wormhole style).
//!
//! All entries are >= 4 ASCII letters and distinct, so a "number-word-word..."
//! code always clears `MIN_SHARED_TOKEN_LEN` and reads back unambiguously. The
//! list is intentionally compact (low entropy per word) - typeability is the
//! goal; the verifier caps pairing attempts to keep that safe.

/// 64 words -> 6 bits each.
pub const WORDS: &[&str] = &[
    "amber", "anchor", "apple", "arrow", "autumn", "bacon", "badge", "banjo",
    "basil", "beacon", "belt", "birch", "bison", "blaze", "bloom", "brick",
    "bridge", "bronze", "brook", "cabin", "cable", "cactus", "candle", "canyon",
    "carbon", "cedar", "chalk", "cherry", "cliff", "clover", "cobalt", "comet",
    "copper", "coral", "cotton", "crane", "crater", "cricket", "crystal", "dagger",
    "daisy", "delta", "denim", "diamond", "dolphin", "drum", "eagle", "ember",
    "fable", "falcon", "fern", "flame", "flint", "forest", "fossil", "frost",
    "galaxy", "garden", "ginger", "glacier", "granite", "harbor", "hazel", "helmet",
];
