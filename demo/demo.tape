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
Set Width 1200
Set Height 760
Set Padding 22
Set Theme "Catppuccin Mocha"
Set TypingSpeed 32ms
Set WindowBar Colorful
Set WindowBarSize 36

Hide
Type "cd demo/.work/local && export PATH=$PWD/../../../target/release:$PATH AGAT_HOME=$PWD/home && unset NO_COLOR && export PS1='\[\e[1;35m\]agat\[\e[0m\] ❯ ' && clear"
Enter
Sleep 400ms
Show

# the splash: agat with no command
Type "agat"
Sleep 400ms
Enter
Sleep 3.2s
Type "clear"
Enter
Sleep 200ms

# scan a folder agat has never seen — one line per file
Type "# point it at a folder of unknown binaries"
Sleep 600ms
Enter
Type "agat scan suspects --output table"
Sleep 400ms
Enter
Sleep 3.5s

# the full immune report for the AI-rewritten variant
Type "# the AI-rewritten one — same payload, new algorithm"
Sleep 600ms
Enter
Type "agat scan suspects/ai_rewritten.bin"
Sleep 400ms
Enter
Sleep 5.5s

Type "clear"
Enter
Sleep 200ms

# are two samples related? (two trained family variants)
Type "# are these two samples related, and where?"
Sleep 600ms
Enter
Type "agat diff $(agat list | awk '/fam_v1/{print $1}') $(agat list | awk '/fam_v5/{print $1}') | head -22"
Sleep 400ms
Enter
Sleep 5s

# pipeline: SARIF + exit code
Type "# drop it into CI — SARIF out, exit code gates the build"
Sleep 600ms
Enter
Type "agat scan suspects --sarif > agat.sarif; echo exit=$?"
Sleep 400ms
Enter
Sleep 2.5s
