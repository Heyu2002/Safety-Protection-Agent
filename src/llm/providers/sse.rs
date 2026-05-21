#[derive(Debug, Default)]
pub(super) struct SseDecoder {
    buffer: String,
}

impl SseDecoder {
    pub(super) fn push(&mut self, chunk: &str) -> Vec<String> {
        self.buffer.push_str(chunk);
        let mut events = Vec::new();

        loop {
            let Some((index, separator_len)) = next_event_separator(&self.buffer) else {
                break;
            };
            let raw_event = self.buffer[..index].to_owned();
            self.buffer.drain(..index + separator_len);
            if let Some(data) = event_data(&raw_event) {
                events.push(data);
            }
        }

        events
    }

    pub(super) fn finish(&mut self) -> Vec<String> {
        if self.buffer.trim().is_empty() {
            self.buffer.clear();
            return Vec::new();
        }

        let raw_event = std::mem::take(&mut self.buffer);
        event_data(&raw_event).into_iter().collect()
    }
}

fn next_event_separator(buffer: &str) -> Option<(usize, usize)> {
    let lf = buffer.find("\n\n").map(|index| (index, 2));
    let crlf = buffer.find("\r\n\r\n").map(|index| (index, 4));

    match (lf, crlf) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

fn event_data(raw_event: &str) -> Option<String> {
    let mut lines = Vec::new();
    for line in raw_event.lines() {
        let line = line.trim_end_matches('\r');
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        lines.push(data.trim_start());
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::SseDecoder;

    #[test]
    fn decodes_split_sse_events() {
        let mut decoder = SseDecoder::default();

        assert!(decoder.push("data: {\"a\"").is_empty());
        assert_eq!(
            decoder.push(":1}\n\ndata: [DONE]\n\n"),
            vec!["{\"a\":1}".to_string(), "[DONE]".to_string()]
        );
    }

    #[test]
    fn flushes_final_event_without_separator() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push("data: last").is_empty());

        assert_eq!(decoder.finish(), vec!["last".to_string()]);
    }
}
