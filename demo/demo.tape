# Renders docs/assets/demo.gif — the README's terminal demo.
#
#   cargo build --release -p agat-cli
#   demo/run.sh            # trains the demo model in demo/.work/local
#   vhs demo/demo.tape
#
# Everything shown is real output from the trained demo model.

Output docs/assets/demo.gif

Require bash

Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 15
Set Width 1180
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set WindowBar Colorful
Set WindowBarSize 36

Hide
Type "cd demo/.work/local && export PATH=$PWD/../../../target/release:$PATH AGAT_HOME=$PWD/home && unset NO_COLOR && export PS1='\[\e[1;36m\]agat\[\e[0m\] ❯ ' && clear"
Enter
Sleep 500ms
Show

Type "# a folder of binaries agat has never seen"
Sleep 700ms
Enter
Type "agat scan suspects --output table"
Sleep 500ms
Enter
Sleep 4s

Type "# zoom in: an AI-rewritten variant — new algorithm, same payload"
Sleep 700ms
Enter
Type "agat scan suspects/ai_rewritten.bin | head -30"
Sleep 500ms
Enter
Sleep 7s

Type "clear"
Enter
Type "# drop it into CI: SARIF out, the exit code gates the build"
Sleep 700ms
Enter
Type "agat scan suspects --sarif > agat.sarif; echo exit=$?"
Sleep 500ms
Enter
Sleep 3s
Type "grep -c ruleId agat.sarif   # one finding per non-clean file"
Sleep 500ms
Enter
Sleep 4s
