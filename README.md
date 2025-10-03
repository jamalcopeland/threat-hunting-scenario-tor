<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/jamalcopeland/threat-hunting-scenario-tor/blob/main/scenario-creation.md)

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

I searched the DeviceFileEvents table for any file that had the string “tor” in it and discovered that the user “employee” downloaded a Tor installer. This resulted in many Tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at `2025-10-02T09:15:23.0000000Z`.

**Query used to locate events:**

```kql
// Installer Name == "tor-browser-windows-x86_64-portable-14.5.7.exe"
// Detect the installer being downloaded
DeviceFileEvents
| where DeviceName == "malthreatvm"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuser"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1873" height="857" alt="step1" src="https://github.com/user-attachments/assets/de08990e-f5f6-4fed-8cc1-5932a7ba461c" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched the Device ProcessEvents table for any ProcessCommanLine that contained the string
`"Tor-browser-windows-x86_64-portable-14.5.7.exe"`. Based on the logs an employee on the `malthreatvm` device ran the file `“tor-browser-windows-x86_64-portable-14.5.7.exe”` from their Downloads folder, using a command that triggered a silent installation.


**Query used to locate event:**

```kql

//Tor Browser was silently installed
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.7.exe"
| where DeviceName == "malthreatvm"
| project Timestamp, FileName, DeviceName, ActionType, ProcessCommandLine, Account = AccountName
```
<img width="975" height="119" alt="image" src="https://github.com/user-attachments/assets/c91162ed-1030-43e3-8e19-a06447f2f0de" />


---

### 3. Searched the `DeviceFileEvents` Table

Searched the `DeviceFileEvents` table for any ProcessCommandLine that contained the string
`"Tor-browser-windows-x86_64-portable-14.5.7.exe"`. Based on the logs, InitiatingCommandLine `"Tor-browser-windows-x86_64-portable-14.5.7.exe"` created two new files: `tor.exe` and `firefox.exe`.


**Query used to locate event:**

```kql
// Tor browser or service was installed and is present on disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| where DeviceName == "malthreatvm"
| project Timestamp, FileName, DeviceName, ActionType, InitiatingProcessFileName
```
<img width="975" height="202" alt="image" src="https://github.com/user-attachments/assets/f38d2210-2d62-490a-b458-66da977ab93a" />



---

### 4. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the `DeviceProcessEvents` table for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at `2025-10-02T09:18:12.0000000Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards


**Query used to locate events:**

```kql
// Tor browser or service was installed and is present on disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| where DeviceName == "malthreatvm"
| project Timestamp, FileName, DeviceName, ActionType, InitiatingProcessFileName
```
<img width="975" height="588" alt="image" src="https://github.com/user-attachments/assets/6a2f38b2-4b7a-4946-b445-04dd9294fa82" />
---

### 5. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-10-02T09:15:23.0000000Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "malthreatvm"
| where InitiatingProcessFileName has_any ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

```
<img width="975" height="219" alt="image" src="https://github.com/user-attachments/assets/57e4d3f1-e221-4e3e-b8e2-d848f2905d22" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-10-02T09:15:23.0000000Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-10-02T09:16:28.0000000Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-10-02T09:18:12.0000000Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-10-02T09:19:03.0000000Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-10-02T09:20:22.0000000Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-10-02T09:21:37.0000000Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-10-02T09:25:14.0000000Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
