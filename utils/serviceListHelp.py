services = []

with open('servicemap.txt','r') as f:
        for line in f:
                line = line.strip()
                servData = line.split('\t')
                service = servData[0]
                servPort = servData[1].split('/')[0]
                servProto = str(servData[1].split('/')[1])
                servFreq = servData[2]
                services.append((service, servPort, servProto, servFreq))
        servicesSorted = sorted(services, key= lambda x: x[3], reverse=True)
        
with open('serviceList.txt','w') as f:
        for service, servPort, servProto, servFreq in servicesSorted:
                f.write(f"{service}, {servPort}, {servProto}, {servFreq}\n")
                