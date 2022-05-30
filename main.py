'''
Main class, initalize everything, and then hand over to sniffer & machine learning model
'''

import sniffer
import glob
import psutil


def main():
    mode = input("Enter s to sniff, or p for pcap analysis. Default will be to sniff traffic.")
    if mode == 'p':
        right = False
        filelist = [f for f in glob.glob('*.pcap*')]
        print(*[str(j + 1) + ' - ' + f for j, f in enumerate(filelist)], sep='\n')
        while not right:
            try:
                a = int(input('Choose file - '))
                if a <= len(filelist):
                    right = True
                    continue
                else:
                    raise ValueError
            except ValueError:
                print('Wrong Input')
        f = filelist[a-1]
        sniffer.main(1, f, ' ')
    else:
        print("Choose interface for sniffing".center(40, ' '))
        ifaces = list(psutil.net_if_addrs().keys())
        ilist = [print(str(j + 1) + ' - ' + str(i)) for j, i in enumerate(ifaces)]
        right = False
        while not right:
            try:
                a = int(input("Choose interface - "))
                if a <= len(ifaces):
                    right = True
                    break
                else:
                    raise ValueError
            except ValueError:
                print("Wrong input")
        iface = ifaces[a - 1]
        sniffer.main(0, '', iface)


if __name__ == '__main__':
    main()
