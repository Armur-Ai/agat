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
Sleep 1.6s

# browse — severity colors
Type "jj"
Sleep 700ms

# mark the selected sample benign
Type "b"
Sleep 1.1s

# open the actions menu — drive the immune pipeline from the UI
Type "a"
Sleep 1.3s

# mature the selected sample into a new family
Type "jj"
Sleep 700ms
Enter
Sleep 800ms
Type "trojan"
Sleep 900ms
Enter
Sleep 1.4s

# refresh verdicts
Type "a"
Sleep 700ms
Type "jjj"
Sleep 500ms
Enter
Sleep 1.1s

# flip through analyzer tabs
Type "l"
Sleep 900ms
Type "l"
Sleep 900ms
Type "1"
Sleep 700ms

# help
Type "?"
Sleep 1.8s
Type " "
Sleep 400ms

Type "q"
Sleep 400ms
