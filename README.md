# CS50 Introduction to Computer Science

**Course link:** **[Ethical Hacker - CISCO](https://cs50.harvard.edu/x/2023/)**<br/>


## Background / Scenario
You have been hired to conduct a penetration test for a customer. At the conclusion of the test, the customer has requested a complete report that includes any vulnerabilities discovered, successful exploits, and remediation steps to protect vulnerable systems. You have access to hosts on the 10.6.6.0/24 and 172.17.0.0/24 networks.
Objectives
For this Final Capstone Activity, you will conduct a complete penetration test starting with reconnaissance and then launching exploits against vulnerabilities that you have discovered. Finally, you will propose remediation for the exploits.	

  - **Challenge 1** – Use SQL injection to find a flag file.
  - **Challenge 2** – Use web server vulnerabilities to investigate directories and find a flag file.
  * **Challenge 3** – Exploit open Samba shares to access a flag file.
  * **Challenge 4** – Analyze a Wireshark capture file to find the location of a file containing flag information.

In this final capstone, we will use DVWA (Damn Vulnerable Web Application) as our testing environment to explore and exploit common web vulnerabilities. DVWA will allow us to practice techniques like SQL injection, crack passwords, and identify security flaws, providing a hands-on approach to understanding how attackers target web applications and how these vulnerabilities can be mitigated.



## Challenge 1: SQL Injection

In this part, you must discover user account information on a server and crack the password of Gordon Brown's account. You will then locate the file that contains the Challenge 1 code and use Gordon Brown's account credentials to open the file at 172.17.0.2 to view its contents.

**Step 1: Preliminary setup**
           
   1. Go to the website at **10.6.6.100**.
   2. Login with the credentials **admin / password**.
   3. Set the **DVWA** security level to **low** and click Submit.

**Step 2: Retrieve the user credentials for the Gordon Brown's account.**

   **Part 1.** Check DVWA to see if a SQL Injection Vulnerability is Present.

Initially, let us employ the following SQL injection payload: ‘OR 1=1 #.

  • ``` ‘ ```  : The single quote is used to terminate the current input string in the SQL query.
  
  • ``` OR 1=1 ``` : This is a logical condition that is always true.
  
  • ``` # ``` : This symbol is used to comment out the rest of the SQL query.


<p align="center">
<img src="" width="650" height="250">
</p>


The output indicates the presence of a vulnerability that allows the execution of SQL statements entered directly into input fields. An 'always true' expression was inputted and processed by the database server, resulting in the retrieval of all records from the database's ID field.

**Part 2.** Check for Number of Fields in the Query

The payload ```1’ ORDER BY 1 #``` is a tool used by attackers to probe the database structure, test for SQL injection vulnerabilities

   • ``` 1’ ``` : Designed to abruptly end a string in an SQL statement.
   
  • ``` ORDER BY ``` : Clause is used to sort the result set of a query by one or more columns.

<p align="center">
<img src="" width="650" height="250">
</p>

By using ```1' ORDER BY 3 #```, you should receive the error message 'Unknown column '3' in 'order clause'.

The error returned by the third string indicates that the query involves two fields. This information is valuable as you proceed with your exploitation efforts.

**Part 3.** Check for version Database Management System (DBMS)

I will now utilize the SQL injection payload ```1' OR 1=1 UNION SELECT 1, VERSION() #``` , which is used to manipulate an SQL query in order to bypass authentication and extract information from a database.

  •  ```UNION SELECT 1, VERSION()``` : Combines the original query results with the results of a new query that retrieves the database version.


<p align="center">
<img src="" width="650" height="250">
</p>

The output 5.5.58-0+deb8u1 indicates the DBMS is MySQL version 5.5.58 running on Debian.

**Part 4.** Determine the database name.

So far you have learned that the database is vulnerable, the query involves two fields, and the DDMS is MySQL 5.5.58.
Next, I will attempt to gather additional schema information about the database by using the SQL injection payload ```1’ OR 1=1 UNION SELECT 1, DATABASE () #``` .

<p align="center">
<img src="" width="650" height="250">
</p>

This means the name of the database is dvwa.
	**Part 5.** Retrieve table Names from the dvwa database.

The payload  ```1' OR 1=1 UNION SELECT 1,table_name FROM information_schema.tables WHERE table_type='base table' AND table_schema='dvwa'#``` is a targeted SQL injection attack used to enumerate table names in a specific database

  •  ```FROM information_schema.tables``` : This specifies that the attacker is querying the information_schema.tables, a special table in most SQL databases that contains metadata about all tables in the database.
  
  •  ```WHERE table_type='base table' AND table_schema='dvwa'``` : This clause filters the results to include only base tables (as opposed to views) from the dvwa database. It ensures the attacker retrieves only relevant table names.


<p align="center">
<img src="" width="650" height="250">
</p>


Two tables were identified: guestbook and users.
Note: The users table is the most interesting, as it may contain usernames and passwords.


**Part 6.** Retrieve column names from the users table.

The SQL injection payload ```1' OR 1=1 UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name='users'#``` is designed to extract the column names from a specific table (in this case, the users table) in a database.

  • ```WHERE table_name='users'```: This clause filters the results to only include columns from the users table.


<p align="center">
<img src="" width="650" height="250">
</p>



Note: The user column and the password column are of interest because they seem to contain information that can be used for unauthorized access.


**Part 7.** Retrieve the user credentials.

The SQL injection payload ```1’ OR 1=1 UNION SELECT user, password FROM users #``` is designed to extract sensitive user data (specifically usernames and passwords) from a database.

   •  ```UNION SELECT user, password``` : In this case, the attacker wants to retrieve the user and password fields from the users table.
   
   •  ```FROM users``` : This specifies the table from which the attacker wants to retrieve the user and password columns.


<p align="center">
<img src="" width="650" height="250">
</p>


Note: The admin account, it probably has the greatest rights and privileges on the system; however, in this capstone project, I will focus on examining the gordonb account.


**Step 3: Crack Gordon Brown's account password.**

I will now use a password hash cracking tool of my choice to recover Gordon Brown’s password. I will implement two approaches: first, by accessing the website ```https://crackstation.net```, and second, by using John the Ripper for the password cracking process.

The information retrieved from the database:

   • First name: gordonb
   
  • Surname: e99a18c428cb38d5f260853678922e03
      
**Part 1.** Free Password Hash Cracker
Access the website https://crackstation.net and copy and paste the hash for the gordonb account “e99a18c428cb38d5f260853678922e03”.


<p align="center">
<img src="" width="650" height="250">
</p>

The outcome is:
  • Hash: e99a18c428cb38d5f260853678922e03

  • Hash Type: MD5
    
  • Cracked Password: abc123
OBS.: MD5 (Message-Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value, typically represented as a 32-character hexadecimal number.



**Part 2.** John the Ripper password cracker
The command  ```echo e99a18c428cb38d5f260853678922e03 > passwd.txt```  is a simple way to write a string (in this case, an MD5 hash) to a file named passwd.txt


<p align="center">
<img src="" width="650" height="250">
</p>

The command  ```john --format=raw-md5 passwd.txt```  tells John the Ripper to crack the MD5 hashes stored in the file passwd.txt.

<p align="center">
<img src="" width="650" height="250">
</p>

With the password successfully cracked, I will now proceed to log in.

<p align="center">
<img src="" width="650" height="250">
</p>


**Step 4: Locate and open the file with Challenge 1 code.**
Open your terminal and run the following command, replacing PASSWORD with the actual password you cracked for Gordon Brown (abc123). Use an SSH client  to log into the server.
    • ```ssh gordonb@172.17.0.2```

<p align="center">
<img src="" width="650" height="250">
</p>

Once logged in, you will typically be in the home directory of the user. To find the flag file, list all files in the home directory using:  ```ls``` .

<p align="center">
<img src="" width="650" height="250">
</p>


**Step 5: Research and propose SQL attack remediation.**

What are five remediation methods for preventing SQL injection exploits?

1. Parameterized Queries: Use parameterized queries or prepared statements to separate SQL code from data. This means that user input is treated as data and not executable code. 
2. Stored Procedures: Utilize stored procedures to encapsulate SQL code within the database. By doing so, you limit the exposure of raw SQL statements to user inputs.
3. Input Validation and Sanitization: Validate and sanitize all user inputs. Ensure that input data conforms to expected formats, types, and lengths.
4. Use of Web Application Firewalls (WAFs): Configure the WAF to filter out known attack patterns and anomalies.
5. Least Privilege Principle: Limit database user permissions to the minimum necessary for the application to function. Avoid using database accounts with administrative privileges for web applications.


## Challenge 2: Web Server Vulnerabilities

In this part, you must find vulnerabilities on an HTTP server. Misconfiguration of a web server can allow for the listing of files contained in directories on the server.

In this challenge, you will locate the flag file in a vulnerable directory on a web server.

**Step 1: Preliminary setup**

  1.  log into the server at 10.6.6.100 with the admin / password credentials.
  2. Set the application security level to low.


Step 2: From the results of your reconnaissance, determine which directories are viewable using a web browser and URL manipulation.
I will adopt two techniques for reconnaissance: Gobuster and Nikto.

**Part 1.** Gobuster 
I will initiate the process by using Gobuster with the following command: ```gobuster dir -u 10.6.6.100:80 -w /usr/share/wordlists/dirb/common.txt```.
    • ``` dir ```: This argument specifies the mode of operation. The dir mode is used for directory brute-forcing, which attempts to find hidden directories and files on a web server.
    
  • ``` -u 10.6.6.100:80 ```: This option specifies the target URL to scan.
      10.6.6.100 is the target IP address, and :80 indicates the HTTP port being used (port 80 is the default for HTTP).
      
  • ``` -w /usr/share/wordlists/dirb/common.txt ``` : The -w option specifies the path to the wordlist file that Gobuster will use for brute-forcing.
      In this case, the wordlist is located at /usr/share/wordlists/dirb/common.txt, which typically contains a list of common directory and file names to check against the target.


<p align="center">
<img src="" width="650" height="250">
</p>

**Part 2.** Nikto
The command ``` nikto -h 10.6.6.100 ``` is used to scan a web server for vulnerabilities and security issues.
    • ```-h 10.6.6.100 ```: The -h option specifies the target host to be scanned.
      In this case, 10.6.6.100 is the IP address of the web server you want to analyze.

<p align="center">
<img src="" width="650" height="250">
</p>

Finding directories such as /docs and /config during a reconnaissance scan with tools like Gobuster or Nikto can provide valuable insights into the structure of a web application and potential vulnerabilities.
/docs → This directory often contains documentation related to the web application or server. It may include API documentation, installation guides, user manuals, or other relevant materials.
/config → This directory typically contains configuration files for the application or server. It may include database connection settings, API keys, or environment configuration.

**Step 3: View the files contained in each directory to find the file containing the flag.**
Access the /docs directory in a web browser to explore its contents

  • ```http://10.6.6.100/docs```


<p align="center">
<img src="" width="650" height="250">
</p>


We were able to locate the user_form.html.

<p align="center">
<img src="" width="650" height="250">
</p>


**Step 4: Research and propose directory listing exploit remediation.**

What are two remediation methods for preventing directory listing exploits?

1. Disable Directory Listings: Configure the web server to prevent directory listings. This can typically be done by modifying the server configuration files (e.g., .htaccess for Apache or nginx.conf for Nginx).
2. Implement Proper Access Controls: Ensure that sensitive directories are protected with appropriate access controls, such as authentication and authorization mechanisms.





## Challenge 3: Exploit open SMB Server Shares

In this section, the objective is to determine whether there are any unsecured shared directories present on an SMB server within the 10.6.6.0/24 network.

**Step 1: Scan for potential targets running SMB.**

By running  ```nmap -sV 10.6.6.0/24``` , you perform a comprehensive scan of the subnet, discovering active hosts, open ports, and the services running on those ports along with their versions. 

  • ```-sV ```: This option enables service version detection. 

<p align="center">
<img src="" width="650" height="250">
</p>

The presence of open ports 139 and 445 suggests that the target system is capable of file sharing, potentially exposing it to various vulnerabilities. 
                  
**Port 139:** NetBIOS Session Service

   • Used for file and printer sharing over a network.
   
   • It allows applications on different computers to communicate with each other in a local area network (LAN).

**Port 445:** SMB (Server Message Block) over TCP

  • This port is primarily used for Windows file and printer sharing.
    
  • It supports shared access to files, printers, and serial ports.

**Step 2: Determine which SMB directories are shared and can be accessed by anonymous users.**

To scan a device running SMB and locate shares that can be accessed by anonymous users, you can use either smbclient or enum4linux. Below are step-by-step instructions for both tools:




**Part 1.** enum4linux

```enum4linux```  is a tool specifically designed for gathering information from Windows machines, particularly useful for enumerating shares and users.

Use the following command to enumerate shares on the target device:

   • ```enum4linux -S 10.6.6.23```

   ```-S```: This option tells enum4linux to enumerate the shares.

The output will include information about the shares available on the target, including those accessible by anonymous users:


<p align="center">
<img src="" width="650" height="250">
</p>

Part 2. smbclient

```smbclient``` is a command-line tool that allows you to access SMB/CIFS resources on servers.
Use the following command to list available shares on the target device:

  • ```smbclient -L //10.6.6.23 -N```
  
``` -L``` : This option tells smbclient to list the shares available on the specified 			        server.
 
```//10.6.6.23``` : This specifies the target SMB server's address. 
  
```-N ```: This flag indicates that you want to connect without a password 		                      (anonymous access). 

When you run the command, you can expect output similar to the following:


<p align="center">
<img src="" width="650" height="250">
</p>


**Step 3: Investigate each shared directory to find the file.**

To investigate each shared directory on an SMB server and find specific files, you can use the smbclient utility.

Use the following command to connect to a specific share:

  • ```smbclient //<target IP>/share_name -N```


<p align="center">
<img src="" width="650" height="250">
</p>

Here, you can use various commands to navigate and list files:

  • ls or dir: Lists the files and directories in the current directory.
  
  • cd <directory_name>: Changes to a specified subdirectory.
  
  • pwd: Displays the current directory path.
  
  • get <file_name>: Downloads a file from the share to your local machine.


<p align="center">
<img src="" width="650" height="250">
</p>

Access the 'OTHER' directory.

<p align="center">
<img src="" width="650" height="250">
</p>


After navigating to the 'OTHER' directory, you can use the get command to download taxes.txt from the share to your local machine.

<p align="center">
<img src="" width="650" height="250">
</p>

<p align="center">
<img src="" width="650" height="250">
</p>


**Step 4: Research and propose SMB attack remediation.**

What are two remediation methods for preventing SMB servers from being accessed?

1. Implement Strong Authentication and Access Controls: Enforce strong password policies and use multi-factor authentication (MFA) for all users accessing the SMB server.
2. Restrict SMB Access via Firewall Rules: Use firewall rules to restrict access to the SMB ports (typically TCP 445 and TCP 139) from untrusted networks or unauthorized IP addresses.





## Challenge 4: Analyze a PCAP File to Find Information.

The capture file, SA.pcap, is located in the OTHER subdirectory within the kali user home directory.

**Step 1: Find and analyze the SA.pcap file.**

Analyze the content of the PCAP file to determine the IP address of the target computer and the URL location of the file with the Challenge 4 code.



<p align="center">
<img src="" width="650" height="250">
</p>

Examine URLs in the "Info" column or follow TCP streams to see paths revealed in the captured traffic.

<p align="center">
<img src="" width="650" height="250">
</p>



**Step 2: Use a web browser to display the contents of the directories on the target computer.**

Use a web browser to navigate to the following URL: ```http://mutillidae.vm/data/```.

<p align="center">
<img src="" width="650" height="250">
</p>

We were able to see the accounts.xml file.


<p align="center">
<img src="" width="650" height="250">
</p>


**Step 3: Research and propose remediation that would prevent file content from being transmitted in clear text.**

What are two remediation methods that can prevent unauthorized persons from viewing the content of the files?

1. Implement Access Control Lists (ACLs): Define user permissions for files and directories to ensure only authorized users can access sensitive information.
2. Encrypt Sensitive Files and Data: Use encryption to convert data into a coded format that can only be read by users with the decryption key.








  
