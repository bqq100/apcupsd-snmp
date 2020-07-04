# Net-SNMP module for apcupsd

This is a re-write of the original implementation, which can be found here:
https://github.com/jirutka/apcupsd-snmp

This is a Net-SNMP module for SNMP monitoring of APC UPSes that don't have SNMP
support. It reads output from apcupsd and writes it into appropriate OIDs like
UPSes with built-in SNMP support, but with rather fewer variables available.

# What use is this?

Why might you want such a thing?  You might have a NAS that you want to monitor
a remote UPS.  In my case I have an APC Back-UPS ES 700 that I use to backup a
NAS and some networking kit.  It used to be that the NAS monitored the UPS directly,
but to maximise my internet connectivity I now want the NAS to suhudown
immediately, and I want something else to monitor the UPS and gracefull shutdown
more and more of the network as teh power declines.

In my new monitoring solution I want to run apcupsd on a Raspbery Pi and have tne NAS
remotely pick up the UPS status from the pi.  The NAS usedes NUT (Network UPS Tools)
to minitor the UPS (both locally and remotely), but the version of NUT installed is
too old to support the apcupsd-ups driver that would allow it to directly monitor
the remote apcupsd instance.  The NAS also supports remote monitoring of SNMP
UPSs, and so by geting my pi to serve the UPS data over SNMP I can point the NAS
to the pi from it's user interface without having to modify the manufacturer's
software.

## Installation
 
To load this into a running agent with embedded Perl support turned on, simply 
put the following line to your snmpd.conf file:

	perl do "/path/to/mod_apcupsd.pl";

Net-snmp must be compiled with Perl support and apcupsd properly configured 
and running!  There is sample snmpd.conf file in the distribution, but I'm
assuming you know how to install and configure both apcupsd and snmpd.

## Use

Try `snmpwalk -v 2c -c public <host> .1.3.6.1.4.1.318.1.1.1` and you should
get something like:

	$ snmpwalk -v 2c -c public localhost .1.3.6.1.4.1.318.1.1.1
	PowerNet-MIB::upsBasicIdentModel.0 = STRING: "Back-UPS RS 500"
	PowerNet-MIB::upsBasicIdentName.0 = STRING: "grid"
	PowerNet-MIB::upsAdvIdentFirmwareRevision.0 = STRING: "30.j2.I USB FW:j2"
	PowerNet-MIB::upsAdvIdentSerialNumber.0 = STRING: "BB0314005xxx"
	PowerNet-MIB::upsBasicBatteryTimeOnBattery.0 = Timeticks: (0) 0:00:00.00
	PowerNet-MIB::upsBasicBatteryLastReplaceDate.0 = STRING: "2009-02-26"
	PowerNet-MIB::upsAdvBatteryCapacity.0 = Gauge32: 100
	PowerNet-MIB::upsAdvBatteryTemperature.0 = Gauge32: 29
	PowerNet-MIB::upsAdvBatteryRunTimeRemaining.0 = Timeticks: (190200) 0:31:42.00
	PowerNet-MIB::upsAdvBatteryNominalVoltage.0 = INTEGER: 12
	PowerNet-MIB::upsAdvBatteryActualVoltage.0 = INTEGER: 13
	PowerNet-MIB::upsAdvInputLineVoltage.0 = Gauge32: 228
	PowerNet-MIB::upsAdvInputFrequency.0 = Gauge32: 49
	PowerNet-MIB::upsAdvInputLineFailCause.0 = INTEGER: blackout(4)
	PowerNet-MIB::upsAdvOutputVoltage.0 = Gauge32: 230
	PowerNet-MIB::upsAdvOutputLoad.0 = Gauge32: 22
	PowerNet-MIB::upsAdvConfigRatedOutputVoltage.0 = INTEGER: 230
	PowerNet-MIB::upsAdvConfigHighTransferVolt.0 = INTEGER: 254
	PowerNet-MIB::upsAdvConfigLowTransferVolt.0 = INTEGER: 198
	PowerNet-MIB::upsAdvConfigAlarm.0 = INTEGER: atLowBattery(2)
	PowerNet-MIB::upsAdvConfigMinReturnCapacity.0 = INTEGER: 0
	PowerNet-MIB::upsAdvConfigSensitivity.0 = INTEGER: high(4)
	PowerNet-MIB::upsAdvConfigLowBatteryRunTime.0 = Timeticks: (24000) 0:04:00.00
	PowerNet-MIB::upsAdvConfigReturnDelay.0 = Timeticks: (0) 0:00:00.00
	PowerNet-MIB::upsAdvConfigShutoffDelay.0 = Timeticks: (0) 0:00:00.00
	PowerNet-MIB::upsAdvTestDiagnosticSchedule.0 = INTEGER: unknown(1)
	PowerNet-MIB::upsAdvTestDiagnosticsResults.0 = INTEGER: 0
	
or if you like numeric OIDs:

	snmpwalk -v 2c -c public -On localhost .1.3.6.1.4.1.318.1.1.1
	.1.3.6.1.4.1.318.1.1.1.1.1.1.0 = STRING: "Back-UPS RS 500"
	.1.3.6.1.4.1.318.1.1.1.1.1.2.0 = STRING: "grid"
	.1.3.6.1.4.1.318.1.1.1.1.2.1.0 = STRING: "30.j2.I USB FW:j2"
	.1.3.6.1.4.1.318.1.1.1.1.2.3.0 = STRING: "BB0314005xxx"
	.1.3.6.1.4.1.318.1.1.1.2.1.2.0 = Timeticks: (0) 0:00:00.00
	.1.3.6.1.4.1.318.1.1.1.2.1.3.0 = STRING: "2009-02-26"
	.1.3.6.1.4.1.318.1.1.1.2.2.1.0 = Gauge32: 100
	.1.3.6.1.4.1.318.1.1.1.2.2.2.0 = Gauge32: 29
	.1.3.6.1.4.1.318.1.1.1.2.2.3.0 = Timeticks: (184800) 0:30:48.00
	.1.3.6.1.4.1.318.1.1.1.2.2.7.0 = INTEGER: 12
	.1.3.6.1.4.1.318.1.1.1.2.2.8.0 = INTEGER: 13
	.1.3.6.1.4.1.318.1.1.1.3.2.1.0 = Gauge32: 228
	.1.3.6.1.4.1.318.1.1.1.3.2.4.0 = Gauge32: 49
	.1.3.6.1.4.1.318.1.1.1.3.2.5.0 = INTEGER: blackout(4)
	.1.3.6.1.4.1.318.1.1.1.4.2.1.0 = Gauge32: 230
	.1.3.6.1.4.1.318.1.1.1.4.2.3.0 = Gauge32: 21
	.1.3.6.1.4.1.318.1.1.1.5.2.1.0 = INTEGER: 230
	.1.3.6.1.4.1.318.1.1.1.5.2.2.0 = INTEGER: 254
	.1.3.6.1.4.1.318.1.1.1.5.2.3.0 = INTEGER: 198
	.1.3.6.1.4.1.318.1.1.1.5.2.4.0 = INTEGER: atLowBattery(2)
	.1.3.6.1.4.1.318.1.1.1.5.2.6.0 = INTEGER: 0
	.1.3.6.1.4.1.318.1.1.1.5.2.7.0 = INTEGER: high(4)
	.1.3.6.1.4.1.318.1.1.1.5.2.8.0 = Timeticks: (24000) 0:04:00.00
	.1.3.6.1.4.1.318.1.1.1.5.2.9.0 = Timeticks: (0) 0:00:00.00
	.1.3.6.1.4.1.318.1.1.1.5.2.10.0 = Timeticks: (0) 0:00:00.00
	.1.3.6.1.4.1.318.1.1.1.7.2.1.0 = INTEGER: unknown(1)
	.1.3.6.1.4.1.318.1.1.1.7.2.3.0 = INTEGER: 0

You can also query only one OID:

	$ snmpwalk -v 2c -c public grid .1.3.6.1.4.1.318.1.1.1.2.2.3.0
	PowerNet-MIB::upsAdvBatteryRunTimeRemaining.0 = Timeticks: (190200) 0:31:42.00

Exactly what you get will depend on what your UPS (and apcupsd) supply.

## What's been changed from the original implementation

* A general tidy-up and re-factoring of the code to remove use of newer perl features
which should make it less dependent on the version of yor system's perl.

* Implementation of the apcupsd NIS protocol in perl so that the script doesn't need
to shell out to /sbin/spcaccess

* Cleaner conversion of values from apcupsd to the values needed by SNMP

* Re-implementation of the GETNEXT handler to better support walking the MIB from
random enrtry points

* Adding error codes to the SNMP responses for unhandled OIDs.

* moving the code into its own namesapce (package) so that it is less likely to
interfere with other net-snmp perl extensions, and introduce a mechanism for
setting config values from snmpd.conf

* Caching and re-using the values returned frm apcupsd - until they are old, and
then stopping reporting.   I'll review the strategy here once I have better
experience of how the NAS uses the values to implement it''s shutdown.

## What can be improved

* Add remaining OIDs that apcupsd could get data for. I included only OIDs for 
the original ai=uthor's APC Back-UPS RS 500 and my APC Back-UPS ES 700.

* Implement support for setting values and traps.

* I'm not a network programmer, and so I'm not convinced I'm handling all the
edge cases for the network connectivity to apcupsd.  I'd welcome a review from
someone who know more than I do in this area.

* Anywhere there's a TODO XXX or FIXME label on a comment is indicative
of something that needs reviewing or improving.

## Important notes

* apcupsd: http://apcupsd.com/

* net-snmp: http://www.net-snmp.org/

* NUT: https://networkupstools.org/

* The latest PowerNet (APC) MIB file I could find is V4.3.2 and can be downloaded from here:
https://www.apc.com/shop/uk/en/products/PowerNet-MIB-v4-3-2/P-SFPMIB432
