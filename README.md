# WFPEnum
Simple bof implementation to enumerate WFP filter and sublayer.  
Two files will be created: 
+ C:\Temp\WFP_Filter_Output.txt (Line 337)
+ C:\Temp\WFP_Sublayer_Output.txt (Line 474)  
### Output Format
+ **Filter**: 
```
#item,Filter Id,Filter Name,Filter Description,Filter Key,Filter Flags,Layer Key,Action Type,Sublayer Key,Filter Weight,No. of Conditions,["Condition Field Key|Condition Match Type|Condition Value",...]
````

+ **Sublayer**:
```
#item,Sublayer Key,Sublayer Name,Sublayer Description,Sublayer Flags,Sublayer Weight
```

### Usage
```
WFPEnum
```

### Compile
```
make
```
### Credits

+ [Aon Cyber Labs EDRSilencer-BOF](https://github.com/AonCyberLabs/EDRSilencer-BOF)