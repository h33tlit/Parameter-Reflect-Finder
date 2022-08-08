<h1 align="center"><img src="https://img.shields.io/badge/Parameter Reflect Finder-Version%3A 1-red?style=for-the-badge"> 🕵🏻‍♂️</h1>
<p>
 <img src="https://img.shields.io/github/issues-raw/h33tlit/Parameter-Reflect-Finder?style=for-the-badge">
 <img src="https://img.shields.io/github/stars/h33tlit/Parameter-Reflect-Finder?color=white&logo=github&style=for-the-badge">
 <img src="https://img.shields.io/github/forks/h33tlit/Parameter-Reflect-Finder?color=white&logo=github&style=for-the-badge">
 <img src="https://img.shields.io/github/commit-activity/m/h33tlit/Parameter-Reflect-Finder?style=for-the-badge">
 
  
  
Parameter-Reflect-Finder is a python based tool that helps you find reflected parameters which can have potential XSS or Open redirection vulnerabilities. After the scan finishes it will fetch all the URLs from alienvault and wayback machine and put it in a text file.
</p>


![image](https://user-images.githubusercontent.com/97327489/173410443-368cbb81-7245-4ef7-b4c9-ce053154aeb7.png)






# Required Packages
1. Json
2. Requests
3. Random

Use "pip" to install all the required packages!

# Usage

```git clone https://github.com/h33tlit/Parameter-Reflect-Finder.git```

```python3 tool.py```

Now enter the domain which you want to scan! It will scan for reflected parameters and show some urls with possible open redirect vulnerabilities.
You can also set max thread to make the script more faster.


# API Used

* OTX
* Wayback


Idea & Concept Credit: <a href="https://github.com/sup3r-b0y">Mrityunjoy</a>
<br/>
Developed by: Jubaer
