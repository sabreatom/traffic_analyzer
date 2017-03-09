from sqlalchemy import *
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

#Packet header analyzing:
class PacketHeader:
    #Constructor:
    def __init__(self, db_name, table_name):
        self.Base = declarative_base()
        
        try:
            self.engine = create_engine('sqlite:///' + db_name, echo=True)
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

def main():
    h_table = PacketHeader('traffic_capture.db', 'packets_1487883055')
    print 'Count from is: ' + str(h_table.count_pckts_from_ip('192.168.1.1'))
    print 'Count to is: ' + str(h_table.count_pckts_to_ip('192.168.1.1'))
        
if __name__ == "__main__":
    main()
