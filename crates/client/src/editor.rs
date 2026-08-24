use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Default, Clone)]
pub struct EditorState {
    text: String,
    cursor: usize,
    preferred_column: Option<usize>,
}

impl EditorState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn set(&mut self, text: String) {
        self.cursor = text.len();
        self.text = text;
        self.preferred_column = None;
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
        self.preferred_column = None;
    }

    pub fn insert(&mut self, value: &str, max_bytes: usize) -> bool {
        if value.is_empty() || self.text.len() >= max_bytes {
            return value.is_empty();
        }
        let line_endings = value.replace("\r\n", "\n").replace('\r', "\n");
        let mut normalized = String::with_capacity(line_endings.len());
        for character in line_endings.chars() {
            match character {
                '\n' => normalized.push('\n'),
                '\t' => normalized.push_str("    "),
                character if character.is_control() => normalized.push('�'),
                character => normalized.push(character),
            }
        }
        let remaining = max_bytes - self.text.len();
        let accepted = if normalized.len() <= remaining {
            normalized.as_str()
        } else {
            let end = normalized
                .grapheme_indices(true)
                .map(|(index, grapheme)| index + grapheme.len())
                .take_while(|end| *end <= remaining)
                .last()
                .unwrap_or(0);
            &normalized[..end]
        };
        self.text.insert_str(self.cursor, accepted);
        self.cursor += accepted.len();
        self.preferred_column = None;
        accepted.len() == normalized.len()
    }

    pub fn move_left(&mut self) {
        self.cursor = previous_grapheme(&self.text, self.cursor);
        self.preferred_column = None;
    }

    pub fn move_right(&mut self) {
        self.cursor = next_grapheme(&self.text, self.cursor);
        self.preferred_column = None;
    }

    pub fn move_start(&mut self) {
        self.cursor = 0;
        self.preferred_column = None;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.text.len();
        self.preferred_column = None;
    }

    pub fn move_line_start(&mut self) {
        self.cursor = self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        self.preferred_column = None;
    }

    pub fn move_line_end(&mut self) {
        self.cursor = self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |index| self.cursor + index);
        self.preferred_column = None;
    }

    pub fn move_vertical(&mut self, direction: isize) {
        let current_start = self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        let current_end = self.text[self.cursor..]
            .find('\n')
            .map_or(self.text.len(), |index| self.cursor + index);
        let column = self
            .preferred_column
            .unwrap_or_else(|| UnicodeWidthStr::width(&self.text[current_start..self.cursor]));
        let target = if direction < 0 {
            if current_start == 0 {
                return;
            }
            let end = current_start - 1;
            let start = self.text[..end].rfind('\n').map_or(0, |index| index + 1);
            (start, end)
        } else {
            if current_end == self.text.len() {
                return;
            }
            let start = current_end + 1;
            let end = self.text[start..]
                .find('\n')
                .map_or(self.text.len(), |index| start + index);
            (start, end)
        };
        self.cursor = byte_at_display_column(&self.text, target.0, target.1, column);
        self.preferred_column = Some(column);
    }

    pub fn delete_backward(&mut self) {
        let previous = previous_grapheme(&self.text, self.cursor);
        if previous != self.cursor {
            self.text.replace_range(previous..self.cursor, "");
            self.cursor = previous;
        }
        self.preferred_column = None;
    }

    pub fn delete_forward(&mut self) {
        let next = next_grapheme(&self.text, self.cursor);
        if next != self.cursor {
            self.text.replace_range(self.cursor..next, "");
        }
        self.preferred_column = None;
    }

    pub fn delete_word_backward(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let before = &self.text[..self.cursor];
        let trimmed = before.trim_end_matches(char::is_whitespace);
        let word_start = trimmed
            .split_word_bound_indices()
            .rfind(|(_, part)| !part.chars().all(char::is_whitespace))
            .map_or(0, |(index, _)| index);
        self.text.replace_range(word_start..self.cursor, "");
        self.cursor = word_start;
        self.preferred_column = None;
    }

    pub fn delete_to_line_start(&mut self) {
        let start = self.text[..self.cursor]
            .rfind('\n')
            .map_or(0, |index| index + 1);
        self.text.replace_range(start..self.cursor, "");
        self.cursor = start;
        self.preferred_column = None;
    }

    pub fn line_count(&self) -> usize {
        self.text.lines().count().max(1)
    }

    pub fn set_cursor_by_visual_position(
        &mut self,
        target_row: usize,
        target_column: usize,
        wrap_width: usize,
    ) {
        let wrap_width = wrap_width.max(1);
        let mut row = 0;
        let mut column = 0;
        let mut last_cursor = 0;
        for (index, grapheme) in self.text.grapheme_indices(true) {
            if grapheme == "\n" {
                if row == target_row {
                    self.cursor = index;
                    self.preferred_column = None;
                    return;
                }
                row += 1;
                column = 0;
                last_cursor = index + grapheme.len();
                continue;
            }
            let width = UnicodeWidthStr::width(grapheme).max(1);
            if column == wrap_width || (column > 0 && column + width > wrap_width) {
                row += 1;
                column = 0;
            }
            if row == target_row && target_column < column + width {
                self.cursor = index;
                self.preferred_column = None;
                return;
            }
            if row > target_row {
                self.cursor = index;
                self.preferred_column = None;
                return;
            }
            column += width;
            last_cursor = index + grapheme.len();
        }
        self.cursor = if row < target_row || target_column >= column {
            self.text.len()
        } else {
            last_cursor
        };
        self.preferred_column = None;
    }
}

fn previous_grapheme(text: &str, cursor: usize) -> usize {
    text[..cursor]
        .grapheme_indices(true)
        .next_back()
        .map_or(cursor, |(index, _)| index)
}

fn next_grapheme(text: &str, cursor: usize) -> usize {
    text[cursor..]
        .grapheme_indices(true)
        .next()
        .map_or(cursor, |(_, grapheme)| cursor + grapheme.len())
}

fn byte_at_display_column(text: &str, start: usize, end: usize, column: usize) -> usize {
    let mut width = 0;
    for (relative, grapheme) in text[start..end].grapheme_indices(true) {
        let next = width + UnicodeWidthStr::width(grapheme);
        if next > column {
            return start + relative;
        }
        width = next;
        if width == column {
            return start + relative + grapheme.len();
        }
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_unicode_by_grapheme() {
        let mut editor = EditorState::new();
        assert!(editor.insert("a👨‍👩‍👧‍👦中", 128));
        editor.move_left();
        editor.delete_backward();
        assert_eq!(editor.as_str(), "a中");
        assert_eq!(editor.cursor(), 1);
    }

    #[test]
    fn vertical_motion_preserves_display_column() {
        let mut editor = EditorState::new();
        editor.set("ab中\n12345".into());
        editor.move_start();
        editor.move_right();
        editor.move_right();
        editor.move_right();
        editor.move_vertical(1);
        assert_eq!(&editor.as_str()[editor.cursor()..], "5");
        editor.move_vertical(-1);
        assert_eq!(editor.cursor(), "ab中".len());
    }

    #[test]
    fn paste_respects_utf8_limit() {
        let mut editor = EditorState::new();
        assert!(!editor.insert("ab中", 4));
        assert_eq!(editor.as_str(), "ab");
        assert!(editor.insert("\r\nc", 8));
        assert_eq!(editor.as_str(), "ab\nc");
    }

    #[test]
    fn paste_cannot_inject_terminal_controls() {
        let mut editor = EditorState::new();
        assert!(editor.insert("safe\x1b[31m\ttext", 128));
        assert_eq!(editor.as_str(), "safe�[31m    text");
    }

    #[test]
    fn mouse_position_accounts_for_wrapping_and_wide_graphemes() {
        let mut editor = EditorState::new();
        editor.set("ab中cd".into());
        editor.set_cursor_by_visual_position(1, 0, 4);
        assert_eq!(&editor.as_str()[editor.cursor()..], "cd");
        editor.set_cursor_by_visual_position(0, 2, 4);
        assert_eq!(&editor.as_str()[editor.cursor()..], "中cd");
    }

    #[test]
    fn deletes_to_line_boundaries() {
        let mut editor = EditorState::new();
        editor.set("first\nsecond line".into());
        editor.move_left();
        editor.delete_to_line_start();
        assert_eq!(editor.as_str(), "first\ne");
    }
}
