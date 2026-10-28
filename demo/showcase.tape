# demo/showcase.tape — the 60-second cinematic showcase (MP4).
#
# Everything shown is REAL output from the trained demo model:
#   cargo build --release -p agat-cli
#   demo/run.sh                 # trains demo/.work/local/home
#   demo/showcase-setup.sh      # builds the 19-file showcase corpus
#   vhs demo/showcase.tape      # -> demo/.work/agat-showcase.mp4
#
# Six beats: logo splash -> an unseen metamorphic variant (full immune
# report) -> an AI-rewritten variant + a behavioral-similarity chart ->
# a folder of unknowns with a live progress sweep and a colored verdict
# table -> the interactive TUI console -> a closing splash.

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
Set TypingSpeed 26ms
Set WindowBar Colorful
Set WindowBarSize 38
Set Framerate 24

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

# ============ beat 1 · the logo (≈6s) ============
Type "agat"
Sleep 400ms
Enter
Sleep 4.5s
Type "clear"
Enter
Sleep 250ms

# ============ beat 2 · an unseen metamorphic variant (≈9s) ============
Type "# a metamorphic variant agat has never seen — no hash, no signature"
Sleep 500ms
Enter
Type "agat scan showcase/mutant_v3.bin"
Sleep 350ms
Enter
Sleep 7s
Type "clear"
Enter
Sleep 250ms

# ============ beat 3 · AI-rewrite + behavioral chart (≈12s) ============
Type "# an AI-rewritten variant — the algorithm was swapped wholesale"
Sleep 500ms
Enter
Type "agat scan showcase/ai_rewrite_1.bin"
Sleep 350ms
Enter
Sleep 4.5s
Type "# two differently-encoded variants — the same behavior underneath?"
Sleep 500ms
Enter
Type "agat diff $(agat list | awk '/fam_v1/{print $1}') $(agat list | awk '/fam_v5/{print $1}')"
Sleep 350ms
Enter
Sleep 5s
Type "clear"
Enter
Sleep 250ms

# ============ beat 4 · a folder of unknowns, live (≈8s) ============
Type "# point it at a folder of unknown binaries"
Sleep 500ms
Enter
Type "agat scan showcase --output table"
Sleep 350ms
Enter
Sleep 6s
Type "clear"
Enter
Sleep 250ms

# ============ beat 5 · the analyst's console (≈17s) ============
Type "# the analyst's console — drive it all from the keyboard"
Sleep 500ms
Enter
Type "agat tui"
Enter
Sleep 2.2s
# walk the fleet; the list recolors by severity, meters update
Type "j"
Sleep 900ms
Type "j"
Sleep 900ms
Type "j"
Sleep 1.2s
# flip through the analysis tabs (meters, antigen, danger fusion)
Type "2"
Sleep 1.4s
Type "5"
Sleep 1.4s
Type "1"
Sleep 1s
# the built-in action menu — no shell required
Type "a"
Sleep 2.2s
Escape
Sleep 700ms
# the help overlay
Type "?"
Sleep 2.2s
Escape
Sleep 600ms
Type "q"
Sleep 500ms

# ============ beat 6 · close on the mark (≈4s) ============
Type "clear"
Enter
Type "agat"
Sleep 400ms
Enter
Sleep 3.5s
