import pyshark
import matplotlib.pyplot as plt
import numpy as np
import os
import nest_asyncio
nest_asyncio.apply()

#graphe the number of packets per minute
def graph_packets_per_minute():
    values=np.array([])
    application=np.array([])
    for filename in os.listdir('/home/emile/EPL/BAC3/Q6/Réseau_Inf/Packet_projet'):
        if filename.endswith(".pcap"):
            capture = pyshark.FileCapture(filename)
            print(filename)
            cap=np.array(capture,dtype=object)
            duration = float(cap[-1].frame_info.time_relative)
            len=cap.size
            ppm=(len/duration)*60
            values=np.append(values,ppm)
            application=np.append(application,filename.removesuffix(".pcap"))
    plt.bar(application,values,color='orange')
    plt.title("Number of packets per minute")
    plt.xlabel("Application")
    plt.ylabel("Number of packets per minute")
    plt.show()


def func(pct, allvalues):
    absolute = int(pct / 100.*np.sum(allvalues))
    return "{:.1f}%\n({:d})".format(pct, absolute)

def graph_type_of_packets(filename):
    duration=float(np.array(pyshark.FileCapture(filename),dtype=object)[-1].frame_info.time_relative)
    types=np.array(['udp','tls','quic','tcp','rtcp'])
    values=np.array([])
    for type in types:
        capture = pyshark.FileCapture(filename,display_filter=type)
        cap=np.array(capture,dtype=object)
        val=(cap.size/duration)*60
        values=np.append(values,val)
    print('ok')
    explode = (0.1, 0.0, 0.2, 0.1, 0.0)
    wp = { 'linewidth' : 1, 'edgecolor' : "green" }
    fig, ax = plt.subplots(figsize =(10, 7))
    wedge, texts, autotexts = ax.pie(values,
                                  autopct = lambda pct: func(pct, values),
                                  explode = explode,
                                  labels = types,
                                  shadow = True,
                                  startangle = 90,
                                  textprops = dict(color ="magenta"))
    ax.legend(types,
          title ="Protocols",
          loc ="center left",
          bbox_to_anchor =(1, 0, 0.5, 1))
    plt.setp(autotexts, size = 8, weight ="bold")
    ax.set_title("Type of packets per minute in following application:"+filename.removesuffix(".pcap").removeprefix("/home/emile/EPL/BAC3/Q6/Réseau_Inf/Packet_projet/"))
    plt.show()

for filename in os.listdir('/home/emile/EPL/BAC3/Q6/Réseau_Inf/Packet_projet'):
    if filename.endswith(".pcap"):
        graph_type_of_packets(filename)

