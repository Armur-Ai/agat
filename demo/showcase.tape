# demo/showcase.tape — the cinematic showcase (MP4): what agat does TODAY,
# then where it grows TOMORROW.
#
#   cargo build --release -p agat-cli
#   demo/run.sh                   # the trained SOC home
#   demo/showcase-setup.sh        # the 19-file scan corpus
#   demo/capabilities-setup.sh    # the un-matured germinal home + signing key
#   vhs demo/showcase.tape        # -> demo/.work/agat-showcase.mp4
#
# NOTE: beat 3 matures the germinal home, so re-run demo/capabilities-setup.sh
# before every render to reset it to the un-matured "before" state.
#
# Everything under "TODAY" is real output from the trained model. The
# "TOMORROW" beat is `agat roadmap` — the tool's own, clearly-labeled map of
# shipped vs roadmap capabilities, never a staged demo of unbuilt features.

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
Set TypingSpeed 19ms
Set WindowBar Colorful
Set WindowBarSize 38
Set Framerate 30

# ---- hidden base setup ----
Hide
Type "cd /Users/akhilsharma/Engineering/agat/demo/.work"
Enter
Type "export PATH=/Users/akhilsharma/Engineering/agat/target/release:$PATH AGAT_VAULT_PASSWORD=agat-demo"
Enter
Type "unset NO_COLOR"
Enter
Type "export PS1='\[\e[1;36m\]agat\[\e[0m\] \[\e[2m\]❯\[\e[0m\] '"
Enter
Type "cd local && clear"
Enter
Sleep 400ms
Show

# ============ beat 1 · the logo (≈4s) ============
Type "agat"
Sleep 400ms
Enter
Sleep 3.5s
Type "clear"
Enter
Sleep 200ms

# ============ beat 2 · TODAY: recognize the unseen (≈8s) ============
Hide
Type "export AGAT_HOME=$PWD/home"
Enter
Type "clear"
Enter
Show
Type "# TODAY · recognize a variant it has never seen"
Sleep 300ms
Enter
Type "agat scan showcase/mutant_v3.bin --theater"
Sleep 250ms
Enter
Sleep 5.5s
Type "clear"
Enter
Sleep 200ms

# ============ beat 3 · TODAY: the germinal center (≈13s) ============
Hide
Type "cd ../germinal && export AGAT_HOME=$PWD/home"
Enter
Type "export V2=$(agat list | awk '/strain_v2/{print $1}') V4=$(agat list | awk '/strain_v4/{print $1}')"
Enter
Type "export V5=$(agat list | awk '/strain_v5/{print $1}') V6=$(agat list | awk '/strain_v6/{print $1}')"
Enter
Type "clear"
Enter
Show
Type "# TODAY · agat learns from the attacks that beat it"
Sleep 300ms
Enter
Type "agat scan variants --output table"
Sleep 250ms
Enter
Sleep 2.2s
Type "# teach it two variants — then watch held-out siblings fall"
Sleep 300ms
Enter
Type "agat mature $V2 --family nightshade && agat mature $V4 --family nightshade"
Sleep 250ms
Enter
Sleep 1.2s
Type "agat scan variants --output table"
Sleep 250ms
Enter
Sleep 2.4s
Type "# one more round — coverage climbs to the whole family"
Sleep 300ms
Enter
Type "agat mature $V5 --family nightshade && agat mature $V6 --family nightshade"
Sleep 250ms
Enter
Sleep 1s
Type "agat scan variants --output table"
Sleep 250ms
Enter
Sleep 2.6s
Type "clear"
Enter
Sleep 200ms

# ============ beat 4 · TODAY: herd immunity (≈10s) ============
Hide
Type "cd ../local && export AGAT_HOME=$PWD/home && rm -rf airgap"
Enter
Type "clear"
Enter
Show
Type "# TODAY · one node immunizes the air-gapped fleet"
Sleep 300ms
Enter
Type "agat repertoire export soc.agatpack --name soc-threats --version 1 --sign keys/soc.key"
Sleep 250ms
Enter
Sleep 2.2s
Type "# carry only the signed pack across the gap — no samples, no telemetry"
Sleep 300ms
Enter
Type "agat --home airgap repertoire import soc.agatpack --trust keys/soc.pub"
Sleep 250ms
Enter
Sleep 2.4s
Type "# the fresh node — which never trained — now catches it"
Sleep 300ms
Enter
Type "agat --home airgap scan showcase/mutant_v3.bin --output table"
Sleep 250ms
Enter
Sleep 2.6s
Type "clear"
Enter
Sleep 200ms

# ============ beat 5 · TOMORROW: the immune roadmap (≈6s) ============
Type "# TOMORROW · where the immune system grows next"
Sleep 300ms
Enter
Type "agat roadmap"
Sleep 250ms
Enter
Sleep 4.5s
Type "clear"
Enter
Sleep 200ms

# ============ beat 6 · the analyst's console (≈9s) ============
Type "# the analyst's console — drive it all from the keyboard"
Sleep 300ms
Enter
Type "agat tui"
Enter
Sleep 2s
Type "j"
Sleep 700ms
Type "j"
Sleep 800ms
Type "a"
Sleep 2s
Escape
Sleep 500ms
Type "q"
Sleep 400ms

# ============ beat 7 · close (≈4s) ============
Type "clear"
Enter
Type "agat"
Sleep 400ms
Enter
Sleep 3s
