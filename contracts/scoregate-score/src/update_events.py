import re

with open(r'c:\Users\User\Desktop\scoregate-contract\contracts\scoregate-score\src\events.rs', 'r') as f:
    content = f.read()

doc_and_const = """// ── Aggregate risk ────────────────────────────────────────────────────────────

/// Event Schema Versioning
/// 
/// All events emitted by this contract carry an explicit schema version in their topic array.
/// The current version for all events is `1`.
/// 
/// Process for bumping:
/// - Append-only changes (adding a new field to the end of the data payload) do not require a version bump.
/// - Any change that alters existing field meaning, order, or removes a field, MUST increment the `EVENT_VERSION`
///   for that specific event or globally to ensure off-chain indexers can detect the shape change.
pub const EVENT_VERSION: u32 = 1;

"""

content = content.replace('// ── Aggregate risk ────────────────────────────────────────────────────────────\n\n', doc_and_const)
content = re.sub(r'\(symbol_short!\("([^"]+)"\)', r'(symbol_short!("\1"), EVENT_VERSION', content)

with open(r'c:\Users\User\Desktop\scoregate-contract\contracts\scoregate-score\src\events.rs', 'w') as f:
    f.write(content)
