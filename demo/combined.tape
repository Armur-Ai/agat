# demo/combined.tape — agat: what it does TODAY, and what's NEXT (one film).
#
# First ~30s: current capabilities — scan a binary it has never seen, an
# AI-rewritten variant, and a whole folder, all live. Next ~30s: the
# capability console prototype — the roadmap immune capabilities as
# selectable actions.
#
#   demo/run.sh && demo/showcase-setup.sh
#   vhs demo/combined.tape   # -> demo/.work/agat-combined.mp4

Output demo/.work/agat-combined.mp4

Require bash
Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 24
Set Width 1800
Set Height 1140
Set Padding 36
Set Theme "Catppuccin Mocha"
Set Margin 69
Set MarginFill "#0a0b14"
Set BorderRadius 24
Set TypingSpeed 20ms
Set WindowBar Colorful
Set WindowBarSize 57
Set Framerate 24

# ---- hidden setup ----
Hide
Type "cd /Users/akhilsharma/Engineering/agat/demo/.work/local"
Enter
Type "export PATH=/Users/akhilsharma/Engineering/agat/target/release:$PATH AGAT_VAULT_PASSWORD=agat-demo AGAT_HOME=$PWD/home"
Enter
Type "unset NO_COLOR"
Enter
Type "export PS1='\[\e[1;36m\]agat\[\e[0m\] \[\e[2m\]❯\[\e[0m\] '"
Enter
Type "clear"
Enter
Sleep 400ms
Show

# ============ PART 1 · TODAY (≈28s) ============
Type "agat"
Sleep 400ms
Enter
Sleep 3.2s
Type "clear"
Enter
Sleep 200ms

Type "# TODAY · scan a binary agat has never seen"
Sleep 300ms
Enter
Type "agat scan showcase/mutant_v3.bin --theater"
Sleep 250ms
Enter
Sleep 6.5s
Type "clear"
Enter
Sleep 200ms

Type "# an AI-rewritten variant — the algorithm was swapped"
Sleep 300ms
Enter
Type "agat scan showcase/ai_rewrite_1.bin --theater"
Sleep 250ms
Enter
Sleep 6.5s
Type "clear"
Enter
Sleep 200ms

Type "# a whole folder of unknowns, at once"
Sleep 300ms
Enter
Type "agat scan showcase --output table"
Sleep 250ms
Enter
Sleep 5s
Type "clear"
Enter
Sleep 200ms

# ============ PART 2 · NEXT: the capability console (≈31s) ============
Type "# NEXT · the capability console — select an action, run it"
Sleep 300ms
Enter
Hide
Type "python3 /Users/akhilsharma/Engineering/agat/demo/roadmap/console.py"
Enter
Sleep 700ms
Show

# intro plays, then the console opens on 'Germinal center'
Sleep 3.5s
Enter
Sleep 4.2s

Type "j"
Sleep 1.5s
Enter
Sleep 4.2s

Type "j"
Sleep 1.5s
Enter
Sleep 4.2s

Type "j"
Sleep 1.5s
Enter
Sleep 4.2s

Type "j"
Sleep 1.5s
Enter
Sleep 4.5s

Type "q"
Sleep 400ms
