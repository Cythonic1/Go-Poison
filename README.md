# Go Poision

## A Arp Poisoning tool in go.


## TODO:

### Add packet sender (Done)
### add dynamic ip or mac discovery
### Pars Command line arguments

## thoughts:
### to achive the dynamic discovery there are two ways:
1. i can make it to construct something like a hash map and discover devices and when the user click something\
    it will stop and then let the user chose which is the target and which is the Default gateway as for the attacker info he can enter them him self.
2. i can make it send a ping message to all devices in the LAN and which response i will be having all info about them Mac and IP and make the attacker life more easier.

## Reference:
https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
