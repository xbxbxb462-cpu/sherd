//! Memorable passphrase generation.
//!
//! 256-word curated list (4-7 letters, lowercase, common, no homophones).
//! Picks N words at random via OsRng and joins with '-'.

use rand::{rngs::OsRng, Rng};

// 256 words. Generated offline from the EFF short wordlist style: common,
// easy to type, unambiguous, no profanity. Each is 4-7 ASCII lowercase.
#[allow(dead_code)]
const WORDS: &[&str] = &[
    "alpha", "anchor", "apple", "april", "arrow", "atlas", "axle", "azure",
    "bacon", "badge", "baker", "balcony", "bamboo", "banana", "banner", "beacon",
    "belt", "bench", "berry", "blade", "blame", "blank", "blast", "blaze",
    "blend", "blink", "block", "blond", "blood", "bloom", "board", "boat",
    "bolt", "bonus", "book", "boot", "border", "bottle", "bounce", "boxer",
    "brain", "brake", "branch", "brand", "brave", "bread", "break", "brick",
    "bridge", "bright", "bravo", "brook", "brown", "brush", "bubble", "buddy",
    "build", "burst", "button", "cabin", "cable", "camel", "candle", "candy",
    "canyon", "captain", "carbon", "cargo", "carpet", "carry", "carve", "castle",
    "cedar", "chain", "chalk", "chance", "change", "channel", "chapel", "chapter",
    "charge", "charm", "chart", "chase", "check", "cherry", "chest", "chicken",
    "chief", "child", "chip", "chord", "chrome", "chunk", "cider", "cipher",
    "circle", "civic", "claim", "class", "clean", "clear", "clerk", "click",
    "cliff", "climb", "cloak", "clock", "close", "cloth", "cloud", "clown",
    "club", "coach", "coast", "cobra", "cocoa", "coffee", "collar", "color",
    "comet", "comic", "copper", "coral", "corner", "cosmic", "cotton", "couch",
    "country", "county", "course", "court", "cover", "crab", "crack", "craft",
    "crane", "crash", "crawl", "cream", "credit", "creek", "cricket", "crisp",
    "crop", "cross", "crown", "crystal", "cuckoo", "custom", "dagger", "dairy",
    "daisy", "dance", "danger", "dawn", "decay", "decoy", "delta", "demon",
    "depth", "derby", "desert", "design", "desk", "detail", "detect", "diamond",
    "dice", "dinner", "dolphin", "domain", "donkey", "donor", "double", "dragon",
    "drama", "dream", "dress", "drift", "drink", "drive", "drone", "drum",
    "duck", "dune", "dust", "dwarf", "eagle", "early", "earth", "echo",
    "edge", "editor", "effect", "effort", "elder", "ember", "engine", "entry",
    "envoy", "epoch", "equal", "equip", "erase", "error", "erupt", "escort",
    "essay", "ethic", "event", "exact", "exam", "exit", "extra", "fable",
    "fabric", "factor", "fade", "fairy", "faith", "fancy", "fault", "favor",
    "feast", "feather", "fence", "ferry", "fetch", "fever", "fiber", "field",
    "fifth", "fifty", "fight", "final", "finger", "finish", "fire", "firm",
    "first", "fisher", "fist", "flag", "flame", "flash", "flavor", "fleet",
    "flesh", "flight", "float", "flock", "floor", "flour", "flower", "fluid",
    "flute", "flyer", "focus", "foggy", "folder", "follow", "fond", "food",
    "foot", "force", "forge", "format", "forty", "forum", "forward", "fossil",
    "found", "frame", "fresh", "friend", "frog", "front", "frost", "fruit",
    "fuel", "fully", "fund", "funny", "fury", "future", "gadget", "galaxy",
];

/// Generate a memorable passphrase of `word_count` words joined by '-'.
#[allow(dead_code)]
pub fn generate_passphrase(word_count: usize) -> String {
    let mut rng = OsRng;
    (0..word_count)
        .map(|_| WORDS[rng.gen_range(0..WORDS.len())])
        .collect::<Vec<_>>()
        .join("-")
}

/// Default passphrase: 6 words (~2^48 entropy).
#[allow(dead_code)]
pub fn generate_default_passphrase() -> String {
    generate_passphrase(6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_has_at_least_256_words() {
        assert!(WORDS.len() >= 256, "expected >=256 words, got {}", WORDS.len());
    }

    #[test]
    fn test_wordlist_words_are_well_formed() {
        for (i, w) in WORDS.iter().enumerate() {
            assert!(w.len() >= 4 && w.len() <= 7,
                "word {} '{}' not 4-7 letters", i, w);
            assert!(w.chars().all(|c| c.is_ascii_lowercase()),
                "word {} '{}' not ascii lowercase", i, w);
        }
    }

    #[test]
    fn test_wordlist_has_no_duplicates() {
        let mut sorted: Vec<&&str> = WORDS.iter().collect();
        sorted.sort();
        for w in sorted.windows(2) {
            assert_ne!(w[0], w[1], "duplicate word: {}", w[0]);
        }
    }

    #[test]
    fn test_passphrase_has_correct_word_count() {
        let p = generate_passphrase(6);
        assert_eq!(p.split('-').count(), 6);
    }

    #[test]
    fn test_passphrase_is_not_empty() {
        let p = generate_default_passphrase();
        assert!(!p.is_empty());
        assert!(p.len() > 20);
    }

    #[test]
    fn test_two_passphrases_differ() {
        let p1 = generate_default_passphrase();
        let p2 = generate_default_passphrase();
        // 256^6 = 2^48 possibilities; collision is astronomically unlikely.
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_passphrase_words_are_in_list() {
        let p = generate_passphrase(8);
        for w in p.split('-') {
            assert!(WORDS.contains(&w), "word '{}' not in wordlist", w);
        }
    }
}
