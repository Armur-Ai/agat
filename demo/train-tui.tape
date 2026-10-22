# Renders docs/assets/train-tui.gif — training agat entirely in the TUI.
# Driven against a fresh, analyzed-but-untrained agat home.
Output docs/assets/train-tui.gif
Require bash
Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 14
Set Width 1320
Set Height 720
Set Padding 18
Set Theme "Catppuccin Mocha"
Set Margin 44
Set MarginFill "#0a0b14"
Set BorderRadius 14
Set WindowBar Colorful
Set WindowBarSize 34

Hide
Type "export PATH=/Users/akhilsharma/Engineering/agat/target/release:$PATH && unset NO_COLOR && clear"
Enter
Show
Type "agat --home /private/tmp/claude-501/-Users-akhilsharma-Engineering-agat/26e83151-5d89-4e1a-9ef3-fe09c5c6cd2e/scratchpad/train/h tui"
Enter
Sleep 1.6s

# mark the four benign tool stubs benign
Type "jjjj"
Sleep 400ms
Type "b"
Sleep 500ms
Type "j"
Type "b"
Sleep 500ms
Type "j"
Type "b"
Sleep 500ms
Type "j"
Type "b"
Sleep 800ms

# build the self-model
Type "a"
Sleep 800ms
Enter
Sleep 1.2s

# generate the repertoire
Type "a"
Sleep 600ms
Type "j"
Sleep 300ms
Enter
Sleep 1.2s

# teach the family on three variants (mal_v4, v3, v2), hold out v1
Type "kkkkkkkk"
Sleep 400ms
# v4 (top)
Type "a"
Sleep 400ms
Type "jj"
Enter
Sleep 400ms
Type "metamorph"
Enter
Sleep 900ms
# v3
Type "j"
Type "a"
Sleep 300ms
Type "jj"
Enter
Sleep 300ms
Type "metamorph"
Enter
Sleep 900ms
# v2
Type "j"
Type "a"
Sleep 300ms
Type "jj"
Enter
Sleep 300ms
Type "metamorph"
Enter
Sleep 1200ms

# the held-out variant v1 now lights up MALICIOUS — recognized unseen
Type "j"
Sleep 2s
Type "q"
Sleep 300ms
