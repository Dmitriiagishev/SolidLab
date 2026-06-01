import pandas as pd

def getPriority(portString):
    try:
        port = int(portString)
    except:
        return 'low', ''
    critical = {22: 'SSH', 
                23:	'Telnet',
                21: 'FTP',
                445: 'SMB',
                3389: 'RDP',
                3306: 'MySQL',
                5432: 'PostgreSQL',
                1433: 'MSSQL',
                27017: 'MongoDB',
                6379: 'Redis',
                9200: 'Elasticsearch',
                80: 'HTTP',
                443: 'HTTPS',
                8080: 'HTTP-Alt',
                8443: 'HTTPS-Alt',}
    
    high = {25: 'SMTP', 
            53: 'DNS', 
            111: 'RPC (portmapper)', 
            135: 'MSRPC', 
            139: 'NetBIOS', 
            389: 'LDAP', 
            636: 'LDAPS', 
            1521: 'Oracle DB', 
            5900: 'VNC', 
            5984: 'CouchDB', 
            11211: 'Memcached', 
            9090: 'Webmin/Cockpit', 
            9418: 'Git', 
            8000: 'App servers',
            8001: 'App servers',
            8002: 'App servers',
            8003: 'App servers',
            8004: 'App servers',
            8005: 'App servers',
            8006: 'App servers',
            8007: 'App servers',
            8008: 'App servers',
            8009: 'App servers',}
    
    medium = {5060: 'SIP (VoIP)',
            5061: 'SIP (VoIP)',
            873: 'Rsync',
            1723: 'PPTP',
            179: 'BGP',
            587: 'SMTP Submission',
            993: 'IMAPS',
            995: 'POP3S',
            2049: 'NFS',
            5985: 'WinRM',
            5986: 'WinRM',
            8888: 'Jupyter/alt HTTP',
            10000: 'Webmin',
            2375: 'Docker API',
            2376: 'Docker API',
            6443: 'Kubernetes API',
            10250: 'Kubelet',
            2379: 'etcd',
            2380: 'etcd',}
    if port in critical:
        return 'critical', critical[port]
    elif port in high:
        return 'high', high[port]
    elif port in medium:
        return 'medium', medium[port]
    else:
        return 'low', ''

if __name__ == "__main__":
    fileName = 'ports3.csv' 
    priorities= {"critical": [],
                 "high": [],
                 "medium": [],
                 "low": []}
    df = pd.read_csv(fileName, sep = ';')
    for portString in df['title']:
        port = portString.split(' ')[-1].split('/')[0]
        priority, service = getPriority(port)
        priorities[priority].append((port, service))

    for priority in priorities:
        if priority != 'low':
            print(priority)
            for entry in priorities[priority]:
                (port, service) = entry
                print(f"\tport: {port}\tservice: {service}")