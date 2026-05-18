pub const DEFAULT_SYSTEM_PROMPT: &str = include_str!("prompts/default.md");

pub const COMPACT_SYSTEM_PROMPT: &str = include_str!("prompts/compact.md");

pub const COMPACTED_CONTEXT_PREFIX: &str = "The conversation history before this point has been compacted. Use this summary as durable context:\n";

pub fn default_system_prompt() -> &'static str {
    DEFAULT_SYSTEM_PROMPT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prompt_defines_defensive_scope() {
        assert!(DEFAULT_SYSTEM_PROMPT.contains("# Mission"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("# Safety Boundaries"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("Safety Protection Agent"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("defensive"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("publicly disclosed vulnerabilities"));
    }

    #[test]
    fn default_prompt_defines_agent_identity() {
        assert!(DEFAULT_SYSTEM_PROMPT.contains("# Identity"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("Your product name is Safety Protection Agent"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("Do not introduce yourself as ChatGPT"));
        assert!(DEFAULT_SYSTEM_PROMPT.contains("underlying model/provider"));
    }

    #[test]
    fn compact_prompt_preserves_operational_context() {
        assert!(COMPACT_SYSTEM_PROMPT.contains("# Compact Conversation History"));
        assert!(COMPACT_SYSTEM_PROMPT.contains("commands"));
        assert!(COMPACT_SYSTEM_PROMPT.contains("configuration keys"));
        assert!(COMPACT_SYSTEM_PROMPT.contains("authorization scope"));
    }
}
