import pandas as pd

class CVEList:
    def __init__(self):
        self.cveList = {'top': [], 'crit': [], 'high' : [], 'med' : [], 'low': [], 'none': []}
        self.lowLimits = {'crit': 9, 'high' : 7, 'med' : 4, 'low': 0, 'none': 0}
        self.fixedVersions = {}

    def addCVE(self, cve):
        if cve.topPriority:
            if cve not in self.cveList['top']:
                self.cveList['top'].append(cve) 
        else:
            if cve not in self.cveList[cve.category]:
                self.cveList[cve.category].append(cve)
    
        if cve.fixedVersion not in self.fixedVersions:
            self.fixedVersions[cve.fixedVersion] = 0 
        self.fixedVersions[cve.fixedVersion] += 1
    
    def sort(self, simple = True):
        if simple:
            for key, CVEList in self.cveList.items():
                CVEList.sort(key=lambda cve: self.fixedVersions[cve.fixedVersion], reverse=True)
            for key, CVEList in self.cveList.items():
                CVEList.sort(key=lambda cve: cve.score, reverse=True)
        else:
            for key, CVEList in self.cveList.items():
                CVEList.sort(key=lambda cve: (cve.score-self.lowLimits[cve.category])**1.1 * self.fixedVersions[cve.fixedVersion], reverse=True)

    def print(self):
        for category in self.cveList:
            if len(self.cveList[category]) > 0:
                print(category)
                for cve in self.cveList[category]:
                    print(f"\t{cve.print()}\t\tpatch fixes: {self.fixedVersions[cve.fixedVersion]} other vulnerabilities")

CVEs = CVEList()

class CVE:
    def __init__(self, score, vulnerabilityID, fixedVersion, attackVector, privilegesRequired):
        category = 'none'
        if float(score) >= 9: category = 'crit'
        elif float(score) >= 7: category = 'high'
        elif float(score) >= 4: category = 'med'
        elif float(score) > 0: category = 'low'
        self.category = category
        self.score = float(score)
        self.vulnerabilityID = vulnerabilityID
        self.fixedVersion = fixedVersion
        self.topPriority = (self.score >= 7 and attackVector == "Network" and privilegesRequired != "Low" and privilegesRequired != "High" and len(str(privilegesRequired)) > 0)

    def print(self):
        return f"{self.vulnerabilityID}{' ' * ((20-len(self.vulnerabilityID)))}{self.score}"
    
def readVulnerabilityCSV(data):
    for score, vulnerabilityID, fixedVersion, attackVector, privilegesRequired in zip(data['Score'], data['Vulnerability Id'], data['Fixed version'], data['CVSS Attack Vector'], data['CVSS Privileges Required']):
        CVEs.addCVE(CVE(score, vulnerabilityID, fixedVersion, attackVector, privilegesRequired))

if __name__ == "__main__":
    fileName = 'qust2.csv' 
    df = pd.read_csv(fileName, sep = ';')
    data = readVulnerabilityCSV(df)
    CVEs.sort(simple = False)
    CVEs.print()