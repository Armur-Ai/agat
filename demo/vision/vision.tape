# demo/vision/vision.tape — the agat VISION film (MP4).
#
# A cinematic, animated depiction of agat's five immune properties operating
# at full strength. Concept/vision piece (each scene carries a dim VISION
# marker); narrate on stage as "how it's expected to run".
#
#   vhs demo/vision/vision.tape   # -> demo/.work/agat-vision.mp4

Output demo/.work/agat-vision.mp4

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

# Start the film under Hide so the invocation never shows; the script
# clears the screen itself, so Show reveals a clean opening logo.
Hide
Type "clear"
Enter
Type "python3 /Users/akhilsharma/Engineering/agat/demo/vision/immune_vision.py"
Enter
Sleep 500ms
Show
Sleep 59s
