# Table of contents

- [Description](#servermon)
- [Setup](#setup)
- [How it works](#how-it-works)
- [The different types of checks](#the-different-types-of-checks)
- [Dispatcher Architecture](#dispatcher-architecture)
- [The GUI](#the-gui)
- [TODO](#todo)
- [License](#license)

## ServerMon

Servermon is a simple Network and server monitoring tool built with PySide6.

## Setup

### Option 1: Installer (Recommended)
```
step 1: Download ServerMon-Setup.exe from the latest release
step 2: Run .exe file and follow along installer
step 3: launch app (from desktop if you chose to make a shortcut to desktop)
```

### Option 2: Running from source (For developers)
```
step 1: git clone https://github.com/your-repo/servermon.git
step 2: cd servermon
step 3: pip install -r requirements.txt
step 4: python main.py
```

## How it works

The tool currently uses an asynchronous, event driven pipeline to handle many types of checks at once,
and to update the many ui objects in use in the GUI of the Tool.

### The different types of checks

1. **PING**
   This type of check resolves the host via DNS and executes an OS ping on windows.

2. **TCP**
   This type of check uses a multi-port scanner using `socket.socket(AF_INET, SOCK_STREAM)`, 
   and evaluates connection handshakes against timeouts and report per-port status (OPEN, CLOSED, TIMEOUT).

3. **HTTP/HTTPS**
   This type of check uses `urllib.request` with a custom `_RedirectTracker` and evaluates HTTP status codes and regex body patterns, 
   includes `_audit_ssl_certificate` to inspect TLS certificates (subject, issuer, expiry date, days remaining).

4. **DNS**
   This type of check constructs binary DNS queries (RFC 1035) via `struct.pack` and sends them over UDP port 53,
   and unpacks 'A' records to verify domain resolution against expected IPs.

5. **SNMP**
   This type of check uses a zero-dependency ASN.1/BER engine: Custom binary encoder/decoder handles SNMP v1/v2c GET and walks over UDP port 161,
   then extracts CPU load, memory, disk usage, and interface traffic counters.

6. **Traffic**
   This type of check is currently not working and is a WIP, it won't do much other than present placeholders, currently the idea was to use
   Wireshark and have the app use it to extract a report of packet captures to monitor bandwidth, packet rates, and TCP retransmissions.

### Dispatcher Architecture

The Registry is essentially the phonebook and conductor for the monitoring system, in earlier versions I had hardcoded in two types of checks; Ping and TCP, however because I wanted to add more types of checks I had to rebuild the entire system for the check and ended up with a phonebook-like system that dispatches the different types of checks to workers with `run_checks_for_target()`.

- `run_checks_for_target()` function does:
  - Reads which checks are enabled
  - Looks up each check function in the registry
  - Runs them all in parallel inside a thread pool
  - Combines the scores into a single result (overall_status, primary_latency_ms)

### The GUI

The graphical interface is the main way to interact and use the tool, once you start the application you will be met with the main dashboard and several other tabs.

- **The header bar**
  - Searchbar allows you to search for an existing entry.
  - Batch check allows you to produce a check for a specific type of check through all server/addresses, running it through a batch worker.
  - The Add Server button allows the user to create a new target entry.

- **The Main Dashboard**
  - **Dashboard overview**:
    The dashboard overview displays the total # of endpoints, # of online server, # of offline server, and the average latency across all monitored servers regardless of type of check.
  - **Recent checks list**:
    This list appends a new entry into a temporary list displaying the last checked server/address.
  - **Quick diagnostics**:
    The quick diagnostic allows you to do just that, you select a server and you get an immediate ping with the primary type of check.

- **Server Directory**
  - The server directory is how you view all servers in a single list, and with a listed brief summary of each server via the information displayed through each column, you are also able to filter through the servers through the filter section just above the list.
  - In the server directory is the place where you select a server and you are able to choose to delete it or edit it.

- **Server Diagnostics (Server Inspector)**
  - This tab is the most complicated one, as it contains most of the detailed information about each server/address, you are also able to enable or disable different types of checks for the currently selected server. (it contains some bugs currently regarding the graphical displays).

- **Activity Log**
  - The Activity Log displays the logs of all checks made, though it only displays a set amount currently of the last ~100, however the logs file logs and maintains all information.
  - For any reason that the Logs might be frozen there is a "Refresh Logs" button.

- **Resource monitor**
  - The resource monitor provides you with information on app resource usage on machine hardware, and monitors and predicts log size after 12hr, and 24hr, in the future you will have a small calculator to measure the log size after however long you would like to measure, it will calculate on hours based on user input or days also based on user input.

- **Settings**
  - The settings page allows you to set the number of concurrent workers, the timeout for checks, and the scheduling settings to set the timer for online and offline servers independently.
  - The insurance system is set here, you can choose the number of consecutive checks the system will make before marking a server offline so as to avoid false offline or online checks.
  - The resource monitor settings are also here for you to set the refresh rate of it.
  - Finally (for now) The alerting and notification setup lies here: you can set up desktop system tray popups(you should be able to toggle the system tray popups but the toggle has not been added yet however it will be implemented soon), as well as the emailing system setup where you set up the SMTP information and the recipients of who will receive the alerts.

## Uninstalling
- **Options**
  -

## TODO

- [ ] **Traffic Monitoring Check**: Finish the Wireshark / tshark integration to replace the current placeholders with live packet capture, bandwidth tracking, and TCP retransmission stats.
- [ ] **Fix Inspector Chart Bugs**: Resolve the visual/graphical rendering glitches in the Server Diagnostics tab.
- [ ] **Log Size Growth Calculator**: Add the interactive calculator to the Resource Monitor tab to project log file size over custom hours or days.
- [ ] **Desktop Notification Toggle**: Add a settings toggle switch to enable/disable desktop system tray popups.
- [ ] **Activity Log Enhancements**: Add search/filter capabilities and configurable line display limits for the log viewer.

## License

This project is licensed under the [Apache License 2.0](LICENSE).


