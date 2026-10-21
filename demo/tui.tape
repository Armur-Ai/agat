# Renders docs/assets/tui.gif — the interactive verdict console.
#   cargo build --release -p agat-cli && demo/run.sh   (trains demo/.work/local)
#   vhs demo/tui.tape
Output docs/assets/tui.gif
Require bash
Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 14
Set Width 1320
Set Height 720
Set Padding 18
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set WindowBarSize 34

Hide
Type "cd demo/.work/local && export PATH=$PWD/../../../target/release:$PATH AGAT_HOME=$PWD/home && unset NO_COLOR && clear"
Enter
Sleep 400ms
Show

Type "agat tui"
Sleep 400ms
Enter
Sleep 1.8s

# browse a few samples — severity colors update live
Type "j"
Sleep 600ms
Type "j"
Sleep 600ms
Type "j"
Sleep 900ms

# flip through the analyzer tabs
Type "l"
Sleep 1s
Type "l"
Sleep 1s
Type "l"
Sleep 1s
Type "1"
Sleep 900ms

# search for the AI-rewritten sample
Type "/"
Sleep 500ms
Type "ai"
Sleep 1.2s
Enter
Sleep 1.4s
Escape
Sleep 600ms

# help overlay
Type "?"
Sleep 2s
Type " "
Sleep 500ms

Type "q"
Sleep 400ms
