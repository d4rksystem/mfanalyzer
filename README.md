# mfanalyzer

A tool for quick and dirty analysis of suspicious files. Designed to run inside Remnux!

Special thanks to all the authors of the tools I invoke with this script!

# A few important points:

- This script should be run in a safe sandbox envronment! Remnux is preferrable (https://remnux.org/.)
- Written in Python 2.7. I know, its old and outdated, but it still works ;)
- This script has some bugs and has no error handling. As mentioned, it is "quick and dirty".

# Example usage and output:

Get a list of all parameters:

> python2.7 mfanalyzer.py --help

Execute the script on an Office Document file:

> python2.7 mfanalyzer.py --doc -s -y -x -o malware.doc

![image](https://user-images.githubusercontent.com/17736813/235953408-766b0d79-170c-4b0b-bfba-759d6f661ffe.png)

Execute the script on a PE Executable file:

> python2.7 mfanalyzer.py --bin -s -y -x -o malware.exe


![image](https://user-images.githubusercontent.com/17736813/235954265-c307277b-1470-4edf-9f29-a948ccf48b63.png)

