# CLI Scanner

A command-line program to scan files in your terminal using the VirusTotal API.

Uses a backend REST API to browse scan history and register devices.
* If you input an 'API Key' and 'API Host' in the configuration file, all scans will send your device name and scan result the given host.
* You can then browse the scan history of all your devices through this online frontend.

---

## MySQL Info:
Password: not4prod

## To research:
* Laravel

## Plan

**1. Frontend: Laravel - PHP, MySQL, Nginx**
* Basic MySQL table, user authentication to view records
* API Endpoints (/create_key, /scan/{device}/{result}/, ...)
* Basic design

**2. Backend: Python - API Communication**
* Create venv
* Parse system args, handle everything, decorators, ...

**3. Dockerize at end?**

---

## Architecture

**1. Backend 'CLI Scanner'**
* Python 3.8
* API Communication

**2. Frontend/API 'View Scan History and User Relationships':**
* [?]
* MySQL 
* PHP - Laravel?
* HTML/CSS

---

All technologies used: Python, PHP, MySQL, HTML, CSS, Laravel, Nginx, Docker [?]

