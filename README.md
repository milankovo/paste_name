# Paste Name

Rename functions, local variables, or structure fields in the Hex-Rays decompiler view using the current clipboard text.

## Usage
- Place the cursor on a function, local variable, or structure field in the decompiler view.
- Copy the desired name to your clipboard.
- Run the "paste name" action (Ctrl+V) to apply the name. The plugin trims trailing underscores and digits commonly added by decompilation.

## Compatibility
- Tested for IDA Pro 9.0 and later
- Platforms: Windows, Linux, macOS (x86_64 and arm64)

## Notes
- The plugin attempts to update the type of locals and members when the clipboard name matches a known type in the database.
- Requires Hex-Rays decompiler to be available.

## License
MIT
