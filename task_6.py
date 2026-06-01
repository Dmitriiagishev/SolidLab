import pandas as pd

# Device;OS;Platform;Product;Vendor;Score;Vulnerability Id;Package Id;CVE;CVE Title;
# LastFixed;FirstDetected;CWE;CWE;
# CVSS Attack Vector;CVSS Attack Complexity;CVSS Privileges Required;CVSS User Interaction;CVSS Scope;CVSS Confidentiality Impact;CVSS Integrity Impact;CVSS Availability Impact
class CVEList:
    def __init__(self):
        self.cveList = {'top': [], 'crit': [], 'high' : [], 'med' : [], 'low': [], 'none': []}
        self.packages = {}

    def addCVE(self, cve):
        if cve.topPriority:
            if cve not in self.cveList['top']:
                self.cveList['top'].append(cve) 
        else:
            if cve not in self.cveList[cve.category]:
                self.cveList[cve.category].append(cve)
        for package in cve.packageID:
            if package not in self.packages:
                self.packages[package] = [] 
            self.packages[package].append(cve)

    def getCoverage(self, cveList, packageList):
        fullCover = 0
        partCover = 0
        for cve in cveList:
            flag = True 
            for package in cve.packageID:
                if package not in packageList:
                    partCover +=1
                    flag = False
                    break
            if flag: fullCover += 1
        return fullCover, partCover
    
    def sort(self):
        for key, CVEList in self.cveList.items():
            CVEList.sort(key=lambda cve: cve.score, reverse=True)
            
    def print(self):
        for category in self.cveList:
            if len(self.cveList[category]) > 0:
                print(category)
                for cve in self.cveList[category]:
                    targetPackages = []
                    c = 0
                    for package in cve.packageID:
                        for p in self.packages[package]:
                            c+=1
                            targetPackages.append(p)
                    cve.fullCover, cve.partCover = self.getCoverage(targetPackages, cve.packageID)
                    print(f"\t{cve.print()}")
CVEs = CVEList()

class CVE:
    def __init__(self, score, vulnerabilityID, packageID, attackVector, privilegesRequired):
        category = 'none'

        if float(score) >= 9: category = 'crit'
        elif float(score) >= 7: category = 'high'
        elif float(score) >= 4: category = 'med'
        elif float(score) > 0: category = 'low'
        self.category = category
        self.score = float(score)
        self.vulnerabilityID = vulnerabilityID
        self.packageID = packageID.split(', ')
        self.topPriority = (self.score >= 7 and attackVector == "Network" and privilegesRequired != "Low" and privilegesRequired != "Medium" and privilegesRequired != "High" and len(str(privilegesRequired)) > 0)
        self.fullCover = 0
        self.partCover = 0

    def print(self):
        return f"{self.vulnerabilityID}{' ' * ((20-len(self.vulnerabilityID)))}{self.score}\t\tPackages: {len(self.packageID)}{' ' * ((8-len(str(len(self.packageID)))))}Full Cover: {self.fullCover}{' ' * (8-len(str(self.fullCover)))}Part Cover: {self.partCover}"
    
def readVulnerabilityCSV(data):
    packages = []
    for packageID in data['Package Id']:
        for package in packageID.split(', '):
            if package not in packages:
                packages.append(package)

    for score, vulnerabilityID, packageID, attackVector, privilegesRequired in zip(data['Score'], data['Vulnerability Id'], data['Package Id'], data['CVSS Attack Vector'], data['CVSS Privileges Required']):
        CVEs.addCVE(CVE(score, vulnerabilityID, packageID, attackVector, privilegesRequired))

if __name__ == "__main__":
    fileName = 'quest1.txt' 
    df = pd.read_csv(fileName, sep = ';')
    data = readVulnerabilityCSV(df)
    CVEs.sort()
    CVEs.print()
