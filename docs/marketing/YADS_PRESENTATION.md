# 🚀 YADS: Das Security Dashboard, das wir alle gebraucht haben

Moin Security-Community! 👋

Habt ihr auch genug von unübersichtlichen Excel-Listen, fragmentierten Tools und Dashboards, die aussehen wie Windows 95? Ich präsentiere euch **YADS (Yet Another Dashboard Security)** – eine moderne, modulare Plattform für Reconnaissance, Asset-Management und Vulnerability Tracking.

Hier ist ein Deep Dive in das, was YADS kann.

---

## 🎯 Dashboard Overview

Alles auf einen Blick. Das Dashboard gibt euch sofortigen Status über alle Targets, laufende Scans und critical Findings. Dark Mode by default, weil wir ja keine Augenkrebs wollen. 😉

![Dashboard Overview](PLACEHOLDER_Dashboard_Main_View.png)

*Key Features:*

* **Real-time Stats:** Aktive Assets, Queue Status, System Health.
* **Status Indicators:** Sofort sehen, was online/offline ist.
* **Recent Activity:** Die letzten Scans und ihre Ergebnisse.

---

## 🌐 Network Graph & Visualisierung

Verstehe deine Infrastruktur visuell. Wer redet mit wem? Welche Subdomains hängen zusammen? Der Network Graph macht komplexe Zusammenhänge sofort sichtbar.

![Network Graph Visualization](PLACEHOLDER_Network_Graph.png)

* **Interactive Force-Graph:** Zoomen, Pannen, Knoten verschieben.
* **Relationship Mapping:** Visualisierung von Subdomains, IPs und Ports.
* **Cluster Detection/Analysis:** Schnell isolierte oder stark vernetzte Assets finden.

---

## 🕷️ Spiderweb & Redirect Analysis

Manchmal ist der Weg das Ziel. Mit der Spiderweb-Ansicht analysieren wir Redirect-Ketten und Entrypoints.

![Spiderweb Analysis](PLACEHOLDER_Spiderweb_Redirects.png)

* **Redirect Chains:** Verfolge HTTP-Redirects bis zum Ziel.
* **Entrypoint Optimization:** Analyse, welche Domain der beste Startpunkt für weitere Tests ist.

---

## 📊 Analytics & Insights

Daten sind schön, aber Insights sind besser. Die Analytics-Page bricht eure Attack Surface herunter.

![Analytics Dashboard](PLACEHOLDER_Analytics_Charts.png)

* **Geo-Distribution:** Wo stehen eure Server? (Interaktive Weltkarte)
* **Tech Stack Analysis:** Welche Webserver und Technologien sind im Einsatz?
* **Security Health:** SSL-Zertifikate, Open Buckets und Reputation Scores.

---

## ⚡ Scanning Modules & Automation

YADS ist nicht nur hübsch, sondern auch laut. Unter der Haube werkelt ein modulares Scanning-Framework.

![Scan Modules In Action](PLACEHOLDER_Scanning_Terminal.png)

* **Recon:** Subdomain Enumeration, DNS Resolution, Port Scanning.
* **Analysis:** Web Tech Detection, Screenshotting (Visual OSINT).
* **Vulnerability:** CVE-Checks, Misconfiguration Scanning.
* **Live Queue & Logs:** Volle Transparenz über das, was der Worker gerade tut.

---

## 🛡️ Multi-Tenancy & RBAC

Gebaut für Teams und Organisationen.

![User Management](PLACEHOLDER_User_Management.png)

* **Mandantenfähigkeit:** Trennung von Daten für verschiedene Kunden/Bereiche (z.B. "a customer").
* **Role Based Access Control:** Viewer, Scanner, Admin Rollen.
* **Audit Logs:** Wer hat wann was gescannt?

---

## 🚀 Fazit

YADS bringt Ordnung in das Chaos der Attack Surface. Es ist Open Source, modern und wird ständig weiterentwickelt.

Checkt es aus und lasst Feedback da!

\#Security #InfoSec #Dashboard #Recon #OpenSource #DevSecOps
