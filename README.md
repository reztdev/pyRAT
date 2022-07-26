Python Remote Administration Tools
----------------------------------


```python
#!/usr/bin/python
# -*- coding: utf-8 -*-

     	 ____  _  _  ____   __  ____
	(  _ \( \/ )(  _ \ / _\(_  _)
	 ) __/ )  /  )   //    \ )(
	(__)  (__/  (__\_)\_/\_/(__) v1.0 (ReztDev)

	Python Remote Administration Tools

class SoftwareEngineer:

    def __init__(self):
    	self.author = "ReztDev"
        self.name = "pyRAT"
        self.role = "Remote Administration Tools"
        self.support = {"windows", "linux"}

    def say_hi(self):
        print("Thanks for dropping by, hope you find some of my work interesting.")

me = SoftwareEngineer()
me.say_hi()
```
## Usage: 
```
python pyrat.py -h / --help for more detail
```


## Run as listen (server):
```
python pyrat.py -s -t 127.0.0.1 -p 4444
```


## Run as listen and generate to output payload:
```
python pyrat.py -s -e -t 127.0.0.1 -p 4444
```

