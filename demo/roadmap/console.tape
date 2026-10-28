# demo/roadmap/console.tape — the agat CAPABILITY CONSOLE (roadmap preview).
#
# An interactive TUI prototype of the future capability console: the five
# roadmap immune capabilities as selectable actions. VHS sends real keystrokes
# (j to move down, ⏎ to run) and the prototype accepts each action.
#
#   vhs demo/roadmap/console.tape   # -> demo/.work/agat-roadmap.mp4

Output demo/.work/agat-roadmap.mp4

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
Set WindowBar Colorful
Set WindowBarSize 38
Set Framerate 30

# launch under Hide so the invocation never shows
Hide
Type "clear"
Enter
Type "python3 /Users/akhilsharma/Engineering/agat/demo/roadmap/console.py"
Enter
Sleep 600ms
Show

# the console opens on 'Germinal center' — read it, then run it
Sleep 2.4s
Enter
Sleep 4s

# move down and run each remaining capability
Type "j"
Sleep 1.6s
Enter
Sleep 4s

Type "j"
Sleep 1.6s
Enter
Sleep 4s

Type "j"
Sleep 1.6s
Enter
Sleep 4s

Type "j"
Sleep 1.6s
Enter
Sleep 4.5s

# quit
Type "q"
Sleep 400ms
