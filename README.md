# threat-hunting-scenario-tor
# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/YtunO/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-05-14T02:38:34.2850051Z`. These events began at `2026-05-14T02:13:22.9731044Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "yet-threathuntl"
| where InitiatingProcessAccountName == "employeey"
| where FileName contains "tor"
| where Timestamp >= datetime(2026-05-14T02:13:22.9731044Z)
|order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1525" height="492" alt="Screenshot 2026-05-14 at 10 14 01 PM" src="https://github.com/user-attachments/assets/6eeb79c8-6e35-4a20-b230-1e21de3e0654" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-05-14T02:17:51.7627676Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-15.0.13.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "yet-threathuntl"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.13.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1522" height="124" alt="Screenshot 2026-05-14 at 10 15 30 PM" src="https://github.com/user-attachments/assets/1e17a4fd-6665-426f-a80d-afbca9630762" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2026-05-14T02:19:14.335467Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql

DeviceProcessEvents
| where DeviceName == "yet-threathuntl"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc 
```
<img width="1513" height="539" alt="Screenshot 2026-05-14 at 10 19 40 PM" src="https://github.com/user-attachments/assets/72b127ed-804a-4103-933c-e0a0bcc18db0" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `22026-05-14T02:19:58.7838251Z`, an employee on the "yet-threathuntl" device successfully established a connection to the remote IP address `81.177.215.43` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employeey\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "yet-threathuntl"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc 
```
<img width="1524" height="413" alt="Screenshot 2026-05-14 at 10 20 19 PM" src="https://github.com/user-attachments/assets/a5228f48-3f21-41c3-a001-8c74ae3fb7ba" />

---

## Chronological Event Timeline

### 1. File Download — TOR Installer
- **Timestamp:** `2026-05-14T02:13:22.9731044Z`
- **Event:** The user "employeey" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.13.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\EmployeeY\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`

### 2. Process Execution — TOR Browser Silent Installation
- **Timestamp:** `2026-05-14T02:17:51.7627676Z`
- **Event:** The user "employeey" executed the file `tor-browser-windows-x86_64-portable-15.0.13.exe` in silent mode, initiating a background installation of the TOR Browser with no visible prompts or windows.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.13.exe /S`
- **File Path:** `C:\Users\EmployeeY\Downloads\tor-browser-windows-x86_64-portable-15.0.13.exe`
- **SHA256:** `04df90b475c3b21b62665d84f625359c8964aaf5e174624cd1eda7a150d314ca`

### 3. Process Execution — TOR Browser Launch
- **Timestamp:** `2026-05-14T02:19:14.335467Z`
- **Event:** User "employeey" opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\EmployeeY\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection — TOR Network
- **Timestamp:** `2026-05-14T02:19:58.7838251Z`
- **Event:** A network connection to IP `81.177.215.43` on port `9001` by user "employeey" was established using `tor.exe`, confirming TOR browser network activity. This means all subsequent browsing was fully anonymized and invisible to corporate security monitoring.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\EmployeeY\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections — TOR Browser Activity
- **Timestamps:**
  - `2026-05-14T02:19:58Z` — Additional connections to TOR relay nodes over port `9001`.
  - `2026-05-14T03:08:59Z` — Final recorded connection to `81.177.215.43` on port `9001`.
  - Multiple connections over port `443` (HTTPS) — TOR disguising traffic as normal web browsing.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employeey" through the TOR browser over approximately 49 minutes of active usage.
- **Action:** Multiple successful connections detected.
- **Process:** `tor.exe`

### 6. File Creation — TOR Shopping List
- **Timestamp:** `2026-05-14T02:13:22.9731044Z` – `2026-05-14T02:19:14Z`
- **Event:** The user "employeey" created a file named `tor-shopping-list.txt` on the Desktop, potentially indicating a premeditated list or notes related to their TOR browser activities. The name strongly suggests intentional and planned use of TOR rather than casual curiosity.
- **Action:** File creation detected.
- **File Path:** `C:\Users\EmployeeY\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employeey" on the device initiated and completed the silent installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network over approximately 49 minutes of active usage, and created a file named `tor-shopping-list.txt` on their Desktop. This sequence of activities indicates the user actively installed, configured, and used the TOR browser for anonymous browsing purposes, with the shopping list file suggesting premeditated and planned use rather than casual curiosity.

---

## Response Taken

TOR usage was confirmed on the endpoint `yet-threathuntl ` by the user `employeey`. The device was isolated, and the user's direct manager was notified.

---
