# Analysis of WiFi-enabled ISP modems #
## Overview ##
SEARCH-LAB Ltd evaluated five home gateway models, all of them are used by many internet service providers worldwide, but the actual devices have been operated by one of the Hungarian Cable TV operators, UPC Magyarország (https://www.upc.hu/). The analysis was executed on commercially available devices and publicly accessible firmware images, obtained from the ISP’s network automatic firmware update mechanism.
We started our analysis with the Ubee EVW3226 modem in June 2015, and after finding several serious issues we contacted UPC Hungary, and its mother company Liberty Global, Inc. (http://www.libertyglobal.com/). After reporting our initial findings, we tested other widely used WiFi routers from Technicolor and Cisco, where we found some more important security flaws that we also reported to Liberty. The evaluation was then extended to include another device made by Hitron, resulting with almost the same level of security problems. 
Presenting this level of vulnerability to the representatives of UPC Magyarorszag and Liberty Global we received two samples from the Compal CH7465LG-LC (Mercury) modems, being one of the most frequently used cable modems in Hungary by UPC. Liberty Global asked SEARCH-LAB to execute the security evaluation of these devices as a pilot project without financial compensation. So as a result SEARCH-LAB can now publish the findings and the Evaluation Report of this research.
So, in November 2015 SEARCH-LAB Ltd. performed a 2-week security evaluation of the Compal CH7465LG-LC in a black-box manner. To illustrate the difference between a quick vulnerability assessment and a systematic evaluation, the pilot project was carried out in two phases: first in a quick 3-hours initial hacking session, and then in a complete systematic 2-weeks long security evaluation and its documentation. Within three hours SEARCH-LAB was able to present to Liberty Global a remotely exploitable code execution vulnerability on the device. The overall evaluation resulted around 35 security flaws.
Since more than half year passed since reporting SEARCH-LAB decided to publish the findings of the above security evaluations.

## Devices evaluated ##
During our analysis, we evaluated the following models:
-	Ubee EVW3226, 1.0.20
-	Technicolor TC7200, STD6.02.11
-	Cisco EPC3925, ESIP-12-v302r125573-131230c_upc
-	Hitron CGNV4, 4.3.9.9-SIP-UPC
-	Compal CH7465LG-LC, CH7465LG-NCIP-4.50.18.13-NOSH

See the results in [Search-lab advisory](http://www.search-lab.hu/advisories/secadv-20150720).
