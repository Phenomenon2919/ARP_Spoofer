# ARP Spoofer
* A simple python3 code to spoof a machine in the same network masquerading as the gateway.
* Code sends ARP response packets to both the target machine and the gateway in loop allowing the host machine to launch further attacks based on MiTM
* Code uses *scapy* package.
* Note: Make sure the target machine is in the same network as the host machine.
## Usage
> pip3 install -r Requirements.txt

In src;
> python3  arp_spoof.py -t \<Target IP> -g \<Gateway IP>