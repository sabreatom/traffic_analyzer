from sqlalchemy import *
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import matplotlib.pyplot as plt

#Packet header analyzing:
class PacketHeader:
    #Constructor:
    def __init__(self, db_name, table_name):
        self.Base = declarative_base()

        try:
            self.engine = create_engine('sqlite:///' + db_name, echo=False)
        except:
            print "Couldn't create SQLite engine!"
            return

        self.metadata = MetaData(bind=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        self.metadata.reflect(self.engine)
        self.header_table = self.metadata.tables[table_name]

    #Count number of packets from specified IP address:
    def count_pckts_from_ip(self, ip_addr):
        count = 0
        for row in self.session.query(self.header_table).filter(self.header_table.columns['IP_ADDR_SRC'] == ip_addr):
            count += 1

        return count

    #Count number of packets to specified IP address:
    def count_pckts_to_ip(self, ip_addr):
        count = 0
        for row in self.session.query(self.header_table).filter(self.header_table.columns['IP_ADDR_DST'] == ip_addr):
            count += 1

        return count

#Flow related analysis:
class PacketHeader_flow(PacketHeader):
    #Constructor:
    def __init__(self, db_name, table_name):
        PacketHeader.__init__(self, db_name, table_name)

    #Calculate total number of packets per second:
    def total_pckts_per_sec(self):
        pckt_count = []
        count = 0
        timestamp = 0
        for row in self.session.query(self.header_table).order_by(asc(self.header_table.columns['ID'])):
            if (timestamp != row[9]):
                if (timestamp != 0):
                    pckt_count.append(count)
                    count = 0
                timestamp = row[9]
            else:
                count = count + 1      
        return pckt_count

    #Calculate number of packets to specific IP address:
    def dest_ip_pckts_per_sec(self, ip_addr):
        pckt_count = []
        count = 0
        timestamp = 0
        for row in self.session.query(self.header_table).filter(self.header_table.columns['IP_ADDR_DST'] == ip_addr)\
            .order_by(asc(self.header_table.columns['ID'])):
            if (timestamp != row[9]):
                if (timestamp != 0):
                    pckt_count.append(count)
                    count = 0
                timestamp = row[9]
            else:
                count = count + 1      
        return pckt_count

#Address related analysis:
class PacketHeader_addr(PacketHeader):
    #Constructor:
    def __init__(self, db_name, table_name):
        PacketHeader.__init__(self, db_name, table_name)

    #Count number of packets from specified IP address:
    def count_pckts_from_ip(self, ip_addr):
        count = 0
        for row in self.session.query(self.header_table).filter(self.header_table.columns['IP_ADDR_SRC'] == ip_addr):
            count += 1
        return count

    #Count number of packets to specified IP address:
    def count_pckts_to_ip(self, ip_addr):
        count = 0
        for row in self.session.query(self.header_table).filter(self.header_table.columns['IP_ADDR_DST'] == ip_addr):
            count += 1
        return count

def main():
    h_table = PacketHeader_addr('traffic_capture.db', 'packets_1487883055')
    print 'Count from is: ' + str(h_table.count_pckts_from_ip('192.168.1.1'))
    print 'Count to is: ' + str(h_table.count_pckts_to_ip('192.168.1.1'))
    h_table2 = PacketHeader_flow('traffic_capture.db', 'packets_1487883055')
    count = h_table2.dest_ip_pckts_per_sec('192.168.1.4')
    plt.plot(xrange(len(count)), count, 'b-')
    plt.show()

if __name__ == "__main__":
    main()
