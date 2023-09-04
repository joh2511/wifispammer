import random, os, argparse, sys
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.sendrecv import sendp


try:
    from scapy.layers.dot11 import (
        Dot11,
        Dot11Beacon,
        Dot11Elt,
        RadioTap)
    from scapy.sendrecv import sendp
except ImportError as err:
    print("Scapy could not be imported.")
    print("Make sure to 'pip3 install scapy'")
    print(err)
    sys.exit(0)


# Generates a random MAC from vendor
def randomMACVendor(vendor):
    generated = ""
    for i in range(0,3):
        generated += ":" + hex(random.randint(0,255))[2:]

    return vendor + generated

# Generates a random MAC
def randomMAC():
    generated = ""
    for i in range(0,6):
        generated += ":" + hex(random.randint(0,255))[2:]

    return generated[1:]

# Gets SSID list from file
def getSSIDs(file):
    SSIDs = []
    ssidList = open(file)
    for line in ssidList.readlines():
        SSIDs.append(line[:-1])
    ssidList.close()

    return SSIDs

# Sets interface in monitor mode
def setIwconfig(interface, value):
    # value can be either monitor or managed
    if value != "monitor" and value != "managed":
        pass

    cmds = [
        f"ip link set dev {interface} down",
        f"iwconfig {interface} mode {value}",
        f"ip link set dev {interface} up",
    ]
    print(f"Setting {interface} in monitor mode...")
    for cmd in cmds:
        exitValue = os.system(cmd)
        if exitValue != 0:
            raise OSError(
                "Something went wrong setting monitor mode! "
                "Are you sure your card supports monitor mode?")


# Sets interface in managed mode
def setManaged(interface):
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode managed")
    os.system(f"ifconfig {interface} up")

vendors = {"Nokia":"C0:41:21", "Apple":"BC:92:6B", 
        "Arduino":"A8:61:0A", "Motorola":"00:E0:0C", "Google":"54:60:09"}
beacon = Dot11Beacon(cap="ESS", timestamp=1)

rsn = Dot11Elt(ID='RSNinfo', info=(
'\x01\x00'              #RSN Version 1
'\x00\x0f\xac\x02'      #Group Cipher Suite : 00-0f-ac TKIP
'\x02\x00'              #2 Pairwise Cipher Suites (next two lines)
'\x00\x0f\xac\x04'      #AES Cipher
'\x00\x0f\xac\x02'      #TKIP Cipher
'\x01\x00'              #1 Authentication Key Managment Suite (line below)
'\x00\x0f\xac\x02'      #Pre-Shared Key
'\x00\x00'))            #RSN Capabilities (no extra capabilities)


def send_beacons(interface, sender, channel, SSIDs):
    last_channel = 0
    for SSID in SSIDs:
        #Switch channel
        next_channel = channel()
        if next_channel != last_channel:
            print(f"Switching channel to {next_channel}")
            result = os.system(f"iw dev {interface} set channel {next_channel}")
            if result != 0:
                raise OSError("Switching channel failed!")
            last_channel = next_channel

        # Create paquet
        print(f"Sending paquet with SSID \"{SSID}\" with MAC: \"{sender}\" ")
        dot11 = Dot11(
            type=0,
            subtype=8,
            addr1='ff:ff:ff:ff:ff:ff',
            addr2=sender,
            addr3=sender)
        essid = Dot11Elt(ID='SSID',info=SSID, len=len(SSID))
        frame = RadioTap() / dot11 / beacon / essid / rsn
        sendp(frame, iface=interface, inter=0.050, loop=0, verbose=1, count=8)

def prepare(interface):
    print("Prepare!")
    os.system(f"nmcli dev set {interface} managed no")
    setIwconfig(interface, "monitor")

def teardown(interface):
    print("Teardown!")
    setIwconfig(interface, "managed")
    os.system(f"nmcli dev set {interface} managed yes")


def main():
    # Check OS
    if sys.platform.lower() != "linux":
        raise OSError("This script only works in Linux!")

    # Check root
    if os.getuid() != 0:
        raise OSError("Must run as root!")

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", default="wifi.lst", help="File to import the SSIDs from (default wifi.lst)")
    parser.add_argument("-v", "--vendor", default="Apple", help="Vendor to spoof (-l to list available vendors)")
    parser.add_argument("-i", "--interface", help="Interface used to spam SSIDs")
    parser.add_argument("-l", "--list-vendors",action="store_true", help="List vendors")
    parser.add_argument("-r", "--random-mac",action="store_true", help="Uses a fully random BSSID instead of using a vendor")
    parser.add_argument("-n", "--count", default=1, help="Number of times to repeat. Use 0 for infinite")
    parser.add_argument("-c",  "--channel", default=0, help="Use 0 for random", type=int)
    args = parser.parse_args()

    # List vendors if -l is present
    if args.list_vendors:
        print("Vendors to choose (default Apple):\n")
        for vendor in vendors:
            print(vendor)
        return

    # Check interface
    if not args.interface:
        raise ValueError("Interface not specified. Extiting...")
    else:
        interfaces = os.listdir("/sys/class/net/")
        if args.interface not in interfaces:
            raise ValueError("Interface not found")

    # Set MAC
    if args.random_mac:
        sender = randomMAC()
    else:
        sender = randomMACVendor(vendors[args.vendor])

    # random channel
    if args.channel < 0 or args.channel > 12:
        raise ValueError("Channel needs to be between 0 and 12")
    if args.channel == 0:
        channel = lambda: random.randint(1,11)
    else:
        channel = args.channel


    # Set interface in monitor mode
    prepare(args.interface)

    # Main loop
    try:
        SSIDs = getSSIDs(args.file)
        count = 0
        while True:
            send_beacons(args.interface, sender, channel, SSIDs)
            count += 1
            if args.count > 0 and count >= args.count:
                break
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        teardown(args.interface)
        print("Done")

if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print("Error occured: " + str(err))
        sys.exit(1)
