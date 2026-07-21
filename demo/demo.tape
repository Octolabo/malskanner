# malskanner demo tape — render with:  vhs demo/demo.tape   (run from repo root)
# Requires https://github.com/charmbracelet/vhs  (brew install vhs)
Output demo/malskanner.gif

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 760
Set Theme "Dracula"
Set TypingSpeed 35ms
Set Padding 20

# --- hidden setup: make sure fixtures exist, then clear the screen ---
Hide
Type "npm run fixtures >/dev/null 2>&1 && clear"
Enter
Sleep 1s
Show

Type "# This README looks completely harmless to a human..."
Enter
Sleep 800ms
Type "cat test/fixtures/poisoned/README.md"
Enter
Sleep 3s

Type "# ...but here's what your AI agent actually ingests:"
Enter
Sleep 800ms
Type "npx tsx src/cli.ts test/fixtures/poisoned"
Enter
Sleep 5s

Type "# REFUSE. The invisible payload is decoded in plain sight."
Enter
Sleep 2500ms
