# demo/showcase.tape — the 60-second cinematic showcase (MP4).
#
# Everything shown is REAL output from the trained demo model:
#   cargo build --release -p agat-cli
#   demo/run.sh                 # trains demo/.work/local/home
#   demo/showcase-setup.sh      # builds the 19-file showcase corpus
#   vhs demo/showcase.tape      # -> demo/.work/agat-showcase.mp4
#
# Seven beats: logo splash -> an unseen metamorphic variant revealed as an
# animated, staged immune scan (agat scan --theater) -> an AI-rewritten
# variant lighting up on LLM-artifact danger signals -> a behavioral-
# similarity chart proving two encodings share one behavior -> a folder of
# unknowns swept into a severity-colored verdict table -> the interactive
# TUI console -> a closing splash.

Output demo/.work/agat-showcase.mp4

Require bash
Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set Margin 46
Set MarginFill "#0a0b14"
Set BorderRadius 16
Set TypingSpeed 24ms
Set WindowBar Colorful
Set WindowBarSize 38
Set Framerate 30

# ---- hidden setup: enter the trained demo tree, colored prompt ----
Hide
Type "cd /Users/akhilsharma/Engineering/agat/demo/.work/local"
Enter
Type "export PATH=/Users/akhilsharma/Engineering/agat/target/release:$PATH"
Enter
Type "export AGAT_HOME=$PWD/home AGAT_VAULT_PASSWORD=agat-demo"
Enter
Type "unset NO_COLOR"
Enter
Type "export PS1='\[\e[1;36m\]agat\[\e[0m\] \[\e[2m\]❯\[\e[0m\] '"
Enter
Type "clear"
Enter
Sleep 500ms
Show

# ============ beat 1 · the logo (≈5s) ============
Type "agat"
Sleep 400ms
Enter
Sleep 4s
Type "clear"
Enter
Sleep 250ms

# ============ beat 2 · an unseen metamorphic variant, revealed live (≈9s) ============
Type "# a metamorphic variant agat has never seen — watch it reason"
Sleep 400ms
Enter
Type "agat scan showcase/mutant_v3.bin --theater"
Sleep 300ms
Enter
Sleep 6.5s
Type "clear"
Enter
Sleep 250ms

# ============ beat 3 · an AI-rewritten variant (LLM artifacts) (≈9s) ============
Type "# an AI-rewritten variant — the algorithm was swapped wholesale"
Sleep 400ms
Enter
Type "agat scan showcase/ai_rewrite_1.bin --theater"
Sleep 300ms
Enter
Sleep 6.5s
Type "clear"
Enter
Sleep 250ms

# ============ beat 4 · two encodings, one behavior (≈7s) ============
Type "# two differently-encoded variants — the same behavior underneath?"
Sleep 400ms
Enter
Type "agat diff $(agat list 2>/dev/null | awk '/fam_v1/{print $1}') $(agat list 2>/dev/null | awk '/fam_v5/{print $1}')"
Sleep 300ms
Enter
Sleep 4.5s
Type "clear"
Enter
Sleep 250ms

# ============ beat 5 · a folder of unknowns, swept live (≈8s) ============
Type "# now point it at a folder of unknown binaries"
Sleep 400ms
Enter
Type "agat scan showcase --output table"
Sleep 300ms
Enter
Sleep 6s
Type "clear"
Enter
Sleep 250ms

# ============ beat 6 · the analyst's console (≈16s) ============
Type "# the analyst's console — drive it all from the keyboard"
Sleep 400ms
Enter
Type "agat tui"
Enter
Sleep 2.2s
Type "j"
Sleep 800ms
Type "j"
Sleep 800ms
Type "j"
Sleep 1.1s
Type "2"
Sleep 1.3s
Type "5"
Sleep 1.3s
Type "1"
Sleep 900ms
Type "a"
Sleep 2.2s
Escape
Sleep 600ms
Type "?"
Sleep 2.2s
Escape
Sleep 500ms
Type "q"
Sleep 500ms

# ============ beat 7 · close on the mark (≈4s) ============
Type "clear"
Enter
Type "agat"
Sleep 400ms
Enter
Sleep 3.5s
