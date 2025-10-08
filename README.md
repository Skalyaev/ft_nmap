# <p align="center">ft_nmap</p>

> Ce projet consiste à recoder une partie de la commande Nmap.
>
> Nmap est un scanner de ports gratuit créé par Fyodor et distribué par Insecure.org.
> Il est conçu pour détecter les ports ouverts, identifier les services hébergés
> et obtenir des informations sur le système d'exploitation d'un ordinateur distant.
>
> Ce logiciel est devenu une référence pour les administrateurs réseau
> car l'audit des rapports Nmap donne des indications sur la sécurité du réseau.
> Il est disponible pour Windows, Mac OS, Linux, BSD et Solaris.
>
> Recoder Nmap va être pour vous l'occasion d'approfondir
> vos connaissances en réseau (TCP/IP) mais aussi de comprendre
> via une utilisation avancée les threads dans un usage réel.
>
> Ce projet est à réaliser en groupe.

## Features

- [x] Host Discovery

  - [x] ICMP Echo probes
  - [x] TCP ACK/CONNECT probes

- [x] Port Scanning

  - [x] TCP SYN
  - [x] TCP NULL
  - [x] TCP FIN
  - [x] TCP XMAS
  - [x] TCP ACK
  - [x] TCP Connect
  - [x] TCP Window
  - [x] TCP Maimon
  - [x] UDP

- [x] OS Detection

  - [x] `WORK IN PROGRESS`

- [x] Firewall/IDS care

  - [x] Fragmentation
  - [x] Source IP manipulation
  - [x] Timing

## Install

```bash
apt update
apt install -y make
apt install -y gcc
```

```bash
git clone https://github.com/Skalyaev/ft_nmap.git
cd ft_nmap && make

./ft_nmap -h
```
