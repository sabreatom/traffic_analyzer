from sqlalchemy import *
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
#import matplotlib.pyplot as plt

#Parameters:
db_name = 'traffic_capture.db'
table_name = 'packets_1493327515'
src_ip_addr = '192.168.1.10'
window_size = 10;
thres = 2

#DB related:
Base = declarative_base()

try:
    engine = create_engine('sqlite:///' + db_name, echo=False)
except:
    print "Couldn't create SQLite engine!"
    exit()
    
metadata = MetaData(bind=engine)
Session = sessionmaker(bind=engine)
session = Session()
metadata.reflect(engine)
header_table = metadata.tables[table_name]

#Calculate packets per second for specific source IP address:
pckt_count = []
count = 0
cur_timestamp = 0
for timestamp, src_addr in session.query(header_table.columns['TIMESTAMP'], header_table.columns['IP_ADDR_SRC']).order_by(asc(header_table.columns['TIMESTAMP'])):
    if (src_addr == src_ip_addr):
        if (cur_timestamp != timestamp):
            if (timestamp != 0):
                pckt_count.append(count)
                count = 0
            cur_timestamp = timestamp
        else:
            count = count + 1

#Plot packets per second from source IP address:
#plt.plot(xrange(len(pckt_count)), pckt_count, 'b-')
#plt.show()

pps_avrg = sum(pckt_count)/len(pckt_count)
print "Average packets per second is: " + str(pps_avrg)
dataset = []
#Create dataset:
for win in range(len(pckt_count) - window_size - 1):
    test_arr = pckt_count[win:win+window_size-1]
    if ((sum(test_arr)/len(test_arr)) > (pps_avrg + thres)):
        dataset.append([test_arr,1])
    else:
        dataset.append([test_arr,0])

print dataset



