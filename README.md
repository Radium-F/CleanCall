Overview :  This is just another implementation of HellsGate_VX technique but with modification by Reenz0h from @SEKTOR7net<br>
            a drawback of HellsGate is that it does not work if the required API(e.g NtOpenProcess) is hooked but Reez0h, patch<br>
            this issue patched technique is call HalosGate.<br>                                                                                                  
	well if a API is hooked where the Systemcall ID has been removed by the AV and overwriten with jump to AV, You can<br> 
            traverse down 32bytes or up -32bytes to the neighboring syscall If the neighboring API function is not being hooked by AV<br> 
	then you can get the systemcall ID and in simple context this is what HalosGate does.<br>
 
  Modification  :  This code performs process injection by taking PID from command line<br>
                   Usage  CleanCall.exe PID

  
  Credits      : Paul Laîné (@am0nsec)<br>
                 smelly__vx (@RtlMateusz)<br>
                 Reez0h
	     

 References : https://vxug.fakedoma.in/papers/VXUG/Exclusive/HellsGate.pdf PDF also included in this repository<br>
              https://blog.sektor7.net/#!res/2021/halosgate.md<br>
	  https://github.com/am0nsec/HellsGate
   

 Please note : !!!!! I do not make any claims !!!, i did this just for learning purpose and modification is one of them.


