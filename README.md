# <p align="center">ft_nmap</p>

> Ce projet consiste à recoder une partie de la commande Nmap.
>
> Nmap est un scanner de ports gratuit créé par Fyodor et distribué par Insecure.org.
> Il est conçu pour détecter les ports ouverts, identifier les services hébergés
> et obtenir des informations sur le système d'exploitation d'un ordinateur distant.
>
> Ce logiciel est devenu une référence pour les administrateurs réseau
> car l'audit des rapports Nmap donne des indications sur la sécurité du réseau.
> Il est disponible pour Windows, Mac OS X, Linux, BSD et Solaris.
>
> Recoder Nmap va être pour vous l'occasion d'approfondir
> vos connaissances en réseau (TCP/IP) mais aussi de comprendre
> via une utilisation avancée les threads dans un usage réel.
>
> Ce projet est à réaliser en groupe.

## Features

- [ ] Host Discovery

  - [ ] `WORK IN PROGRESS`

- [ ] Port Scanning

  - [ ] TCP SYN
  - [ ] TCP Connect
  - [ ] TCP NULL
  - [ ] TCP FIN
  - [ ] TCP XMAS
  - [ ] TCP ACK
  - [ ] TCP Window
  - [ ] TCP Maimon
  - [ ] UDP

- [ ] Service Version Detection

  - [ ] `WORK IN PROGRESS`

- [ ] OS Detection

  - [ ] `WORK IN PROGRESS`

- [ ] Firewall care

  - [ ] Fragmentation
  - [ ] Source port manipulation
  - [ ] MAC address spoofing
  - [ ] Fake RST detection trial

- [ ] IDS care

  - [ ] Decoys
  - [ ] Timing

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
