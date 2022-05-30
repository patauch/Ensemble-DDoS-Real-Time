import csv
import pickle

import traceback


from scapy.sendrecv import sniff
import glob

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

import warnings
warnings.filterwarnings("ignore")

f = open("output_logs.csv", 'w')
w = csv.writer(f)

current_flows = {}
FlowTimeout = 600

normalization = None
classifier = None


def load_model():
    filelist = [f for f in glob.glob('*_model.sav')]
    print(*[str(j + 1) + ' - ' + m for j, m in enumerate(filelist)], sep='\n')
    right = False
    while not right:
        try:
            ch_f = int(input("Choose model - "))
            if ch_f <= len(filelist):
                right = True
                break
            else:
                raise ValueError
        except ValueError:
            print('Wrong Input')
    model = filelist[ch_f-1]
    with open(model, 'rb') as m:
        return pickle.load(m)


def load_scalar():
    with open('scalar.sav', 'rb') as s:
        return pickle.load(s)


def classify(features):
    # preprocess
    f = features

    features = normalization.transform([f])
    result = classifier.predict(features)

    feature_string = [str(i) for i in f]
    classification = [str(result[0])]
    if result !='BENIGN':
        print(classification)

    w.writerow(feature_string + classification)

    return feature_string + classification


def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for fin flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:

            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            # current flows put id, (new) flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def live(iface):
    print("Begin Sniffing".center(20, ' '))
    sniff(iface=iface, prn=newPacket)
    for a in current_flows.values():
        classify(a.terminated())


def pcap(f):
    sniff(offline=f, prn=newPacket)
    for flow in current_flows.values():
        classify(flow.terminated())


def main(mode, pcap_file, iface):
    global classifier
    global normalization
    print("Loading model ".center(20, '~'))
    classifier = load_model()
    normalization = load_scalar()
    print(" Sniffing ".center(20, '*'))
    if mode == 0:
        live(iface)
    else:
        pcap(pcap_file)


if __name__ == '__main__':
    main()
    f.close()
