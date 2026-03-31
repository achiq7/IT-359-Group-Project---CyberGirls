# IT-359-Group-Project---CyberGirls
## Web Application Vulnerability Scanner (Project Proposal) 
Web Application Vulnerabiliity Scanner -- Scans for vulnerabilities on websites and gives report

## Table of Contents
- Team members
- Project Description
- Plan of Action
- Tools
- Deliverables
- Roles
- Timeline

## Team Members
- D'Shanti Williams
- Alyssa Chiquito

## Project Description
As a team, we have decided to create a vulnerability scanner that will be applied to a premade web application called OWSAP Juice Shop. Our tool will be used to scan for vulnerabilities such as SQL injection, HTTP use, cross site scripting, etc. as well as be atutomated. Our plan is to code using Python which will hold the code for vulnerability scanning as well as a HTML/PDF report of all vulnerabilities found within the application. 

## Plan of Action:
  -  Develop a custom python tool that automates vulnerabilty checks
  -  Document the web security findings from the python tool
  -  Create a human readable HTML/PDF report which would include our findings and different mitigation techniques that we recommend
  
## Tools:
  -  Testing target (OWASP Juice Shop)
  -  Python3
  -  Kali Linux Machine
 
## Deliverables:
  -  Investigation
      -  Parse through common vulnerability paths/files
      -  Navigate through common administrator paths
  - Security checks
       -  Security header checks
       -  SQL checks
       -  Certificate checks
       -  Cross Site Scripting checks
   - Output
       - JSON output
       - Produce HTML/PDF report including:
           - Severity rating
           - Mitigation techniques
        
## Roles:
  - Alyssa
      -  README file
      -  Code split evenly
      -  Split report evenly
      -  Presentation slides
  - D'Shanti
      -  Scheduling meetings
      -  Code split evenly
      -  Split report evenly
      -  Presentation slides
   
## AI Aspect:
- After the Python scanner complies its findings, we will leverage AI to output the severity of the findings, CVSS scoring/reasoning behind the score, and how the vulnerability could be exploited by an attacker if left unchecked
- In order to reduce false positives, AI will analyze ambigous data/evidence by interpreting error message patterns and checking two verification steps against each other(baseline vs injected)
- We will use AI to propose remediation methods/suggestions within an executive HTML/PDF report output, based upon analyzing vulnerability findings and evidence (headers, requests, authentication responses, etc)
   
## Timeline:
- Week 1-2: Schedule times/dates available for meetings, learn github commands, and familiarize ourselves with OWASP Juice Shop application (Feb. 8 - 21)
- Week 3-6: Code creation (Feb 22 - Mar. 21)
- Week 7-9: Test tool on web application and begin report (Mar. 22 - Apr. 11)
- Week 11:  Edit code (Apr. 12 - 18)
- Week 12:  Final presentation slides and presentation video (Apr. 19 - May 2)
- Week 13:  Final touches on the presentation slides, video, paper, and GitHub repository (May 3 - May 8)
  



