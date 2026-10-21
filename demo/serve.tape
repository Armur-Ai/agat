# Renders docs/assets/serve.gif — the HTTP API.
#   cargo build --release -p agat-cli && demo/run.sh
#   vhs demo/serve.tape
Output docs/assets/serve.gif
Require bash
Set Shell "bash"
Set FontFamily "JetBrains Mono, Menlo, monospace"
Set FontSize 15
Set Width 1200
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set WindowBar Colorful
Set WindowBarSize 34

Hide
Type "cd demo/.work/local && export PATH=$PWD/../../../target/release:$PATH AGAT_HOME=$PWD/home && unset NO_COLOR && export PS1='\[\e[1;35m\]agat\[\e[0m\] ❯ ' && clear"
Enter
Sleep 300ms
# start the server in the background
Type "agat serve --listen 127.0.0.1:8080 >/tmp/agat-serve.log 2>&1 &"
Enter
Sleep 1.2s
Type "clear"
Enter
Show

Type "# a local scan API — model loaded once, no network out"
Sleep 700ms
Enter
Type "curl -s localhost:8080/healthz | jq"
Sleep 400ms
Enter
Sleep 2.2s

Type "# POST a file, read the severity from the header"
Sleep 700ms
Enter
Type "curl -sD - --data-binary @suspects/unseen_variant.bin 'localhost:8080/v1/scan?name=unseen_variant.bin' -o /tmp/r.json | grep -i x-agat"
Sleep 400ms
Enter
Sleep 2.2s

Type "jq '{severity: .verdict.severity, family: .recognition.family, danger: .danger.context}' /tmp/r.json"
Sleep 400ms
Enter
Sleep 2.5s

Hide
Type "kill %1 2>/dev/null"
Enter
Show
Sleep 300ms
